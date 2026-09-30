#!/usr/bin/env python3
"""The outside status checker: asks, from outside the server, what a visitor
and a click depend on, and emails when the answer is no.

The app cannot report its own outage: when it is down, nothing inside it runs
to notice. `.github/workflows/status-check.yml` runs this on GitHub's
runners, every five minutes from the checker's own public repo,
independent of the server and of Mailgun. Standard library only, so the
workflow installs nothing.

What it asks:
- `<site>/api/health` answers 200 with status "ok". A 503 "degraded" means the
  app answers but its database does not, and that fails.
- The home page answers 200.
- When STATUS_CHECK_TRACKING_URL is set, the tracking host answers its own
  `/api/health`. Never a tracking link: a GET of `/t/o/...` or `/t/c/...`
  records an open or a click (a HEAD there is refused, app/spa.py), and
  `/api/health` records nothing.
- When STATUS_CHECK_PRIVACY_URLS is set (full https:// addresses, separated
  by spaces or commas, three at most), each passes the owners' two checks on
  the privacy page the carrier's reputation enrolment for every recruiter
  number cites: it answers 200, and its HTML says
  "Privacy Policy". It is asked as their curl asks, following no redirect,
  so a redirect fails, naming where it pointed.
- Each HTTPS host's certificate, the privacy pages' included, has at least
  14 days left. Let's Encrypt renews at 30, so under 14 means renewals are
  failing.

One slow answer is not an incident: after any failure it waits 90 seconds and
asks everything again, and only a second failure fails the run.

A failed run exits 1, so the run history shows the outage, and it emails
STATUS_ALERT_TO over the company SMTP server, never Mailgun: when a failure
starts, every four hours while it lasts, and once when it passes again. It
keeps no state of its own: `alert_due` works the cadence out from the
workflow's earlier runs, read with the run's own GITHUB_TOKEN.

With STATUS_CHECK_TOKEN set, the token an admin makes on the site's Settings ->
Monitoring, it then posts each run's result to `<site>/api/status-check`, which
the dashboard's `outside-check` reads. A report the site doesn't take is said
plainly (a 401 means the two tokens differ) and fails nothing: the site checks
decide the run.

By hand, with only STATUS_CHECK_SITE_URL set, it checks, reports and emails
nobody: `python scripts/status_check.py`.
"""
from __future__ import annotations

import json
import os
import smtplib
import socket
import ssl
import sys
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid, parseaddr
from http import HTTPStatus
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

#: The workflow that runs this script. Its earlier runs are the checker's memory.
WORKFLOW_FILE = "status-check.yml"
#: The workflow step that runs this script. A failed run whose step failed
#: judged the site failing; one that failed before the step judged nothing.
CHECK_STEP = "Check the site"

#: Seconds a request or a TLS handshake may take, and an SMTP exchange.
TIMEOUT_SECONDS = 10
SMTP_TIMEOUT_SECONDS = 20
#: One slow answer is not an incident: after a failure, everything is asked
#: again this many seconds later, and only a second failure counts.
RETRY_AFTER_SECONDS = 90
#: Let's Encrypt renews at 30 days left, so under 14 means renewals are failing.
CERTIFICATE_DAYS_MIN = 14
#: While a failure lasts, a reminder every four hours, as the app's alerts do.
REMIND_EVERY = timedelta(hours=4)
#: GitHub starts scheduled runs late, by minutes and sometimes more, so a
#: four-hour mark counts as reached half an hour early: the fourth hourly run
#: after the start reminds, even when the start ran late.
SCHEDULE_SLACK = timedelta(minutes=30)
#: Earlier runs read, newest first: about four days of hourly runs.
HISTORY_RUNS = 100
#: Failed runs looked into, newest first, to tell one that judged the site
#: failing from one that broke before it asked. One is usually enough.
LOOK_INTO_AT_MOST = 5

USER_AGENT = "ab-www-status-check/1 (GitHub Actions)"
MAX_BODY_BYTES = 65536

#: The privacy page the carrier's reputation enrolment for every recruiter
#: number cites, by full address, and what the owners' second check greps its
#: HTML for. Their grep reads the whole page; this reads up to a megabyte.
PRIVACY_URLS = "STATUS_CHECK_PRIVACY_URLS"
PRIVACY_PHRASE = "Privacy Policy"
MAX_PAGE_BYTES = 1 << 20

ALERT_TO = "STATUS_ALERT_TO"
SMTP_SECRETS = (
    "STATUS_SMTP_HOST", "STATUS_SMTP_PORT", "STATUS_SMTP_USERNAME",
    "STATUS_SMTP_PASSWORD", "STATUS_SMTP_FROM",
)

#: The secret that lets a run's result reach the dashboard, and where it goes.
TOKEN = "STATUS_CHECK_TOKEN"
REPORT_PATH = "/api/status-check"
#: What the site keeps of each check's name and detail (backend
#: `models/status_check.py`, held equal by the tests): longer is cut here.
REPORT_NAME_LIMIT = 80
REPORT_DETAIL_LIMIT = 300
#: The site keeps 12 checks a run. The site's two, the tracking host's and a
#: certificate for each host leave room for three privacy pages: 11 in all.
PRIVACY_URLS_MAX = 3
#: The token travels over HTTPS only, except to this machine, for a run by hand.
LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})

#: The three emails.
FAILING, STILL_FAILING, PASSING_AGAIN = "failing", "still failing", "passing again"

#: What each failure costs, in the company's words.
API_MEANS = ("The app or its database isn't answering: the blog, sign-in, the admin "
             "and the demo form fail.")
HOME_MEANS = "Visitors get an error instead of the website."
TRACKING_MEANS = ("Clicks and opens from mail already sent don't reach the app: a "
                  "campaign's links lead nowhere.")
CERTIFICATE_LOW_MEANS = ("Browsers will refuse the site when it expires. Let's Encrypt "
                         "renews at 30 days left, so under 14 means renewals are failing: "
                         "runbook step I6 has how this name renews.")
CERTIFICATE_REFUSED_MEANS = "Browsers refuse the site now."
CERTIFICATE_UNREAD_MEANS = "The certificate couldn't be read, so its days left are unknown."
PRIVACY_MEANS = ("The carrier's reputation enrolment for every recruiter phone number cites "
                 "this address: it must answer a plain 200 with the policy's text, never a "
                 "redirect, or the numbers can be flagged as spam.")


# --- asking the site ----------------------------------------------------------

@dataclass(frozen=True)
class Answer:
    """An HTTP answer: its status, the start of its body, and where it points
    when it is a redirect."""
    status: int
    body: bytes = b""
    location: str = ""


@dataclass(frozen=True)
class Result:
    """One check: what it asked, whether it passed, and what it saw, in words."""
    name: str
    target: str
    ok: bool
    saw: str
    means: str = ""


def error_answer(error: HTTPError) -> Answer:
    """An error status, as an answer: the status, the start of its body and,
    for a redirect not followed, where it points."""
    body = b""
    if error.fp is not None:
        try:
            body = error.read(MAX_BODY_BYTES)
        except OSError:
            pass  # the status is the answer; its body is only detail
        finally:
            error.close()
    location = error.headers.get("Location") if error.headers is not None else None
    return Answer(error.code, body, str(location or ""))


def http_get(url: str) -> Answer:
    """GET `url`, following redirects as a browser would. An error status is an
    answer; getting none at all raises."""
    request = Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
            return Answer(response.status, response.read(MAX_BODY_BYTES))
    except HTTPError as error:
        return error_answer(error)


class NoRedirects(HTTPRedirectHandler):
    """Follows no redirect, so a 3xx comes back as the answer. The report
    needs it: urllib would carry the Authorization header to wherever one
    points, and turn the POST into a GET. So does a privacy page, which the
    owners' check asks as it is: a redirect there is itself the failure."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http_get_no_redirects(url: str) -> Answer:
    """GET `url` as the owners' curl does, following no redirect: a 3xx is the
    answer, with where it points. An error status is an answer; getting none
    at all raises."""
    request = Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with build_opener(NoRedirects).open(request, timeout=TIMEOUT_SECONDS) as response:
            return Answer(response.status, response.read(MAX_PAGE_BYTES))
    except HTTPError as error:
        return error_answer(error)


def http_post(url: str, token: str, payload: Mapping) -> Answer:
    """POST `payload` as JSON with the token as a bearer credential. An error
    status is an answer, a redirect included; getting none at all raises."""
    request = Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    })
    try:
        with build_opener(NoRedirects).open(request, timeout=TIMEOUT_SECONDS) as response:
            return Answer(response.status, response.read(MAX_BODY_BYTES))
    except HTTPError as error:
        return error_answer(error)


def certificate_expiry(host: str, port: int) -> datetime:
    """When the certificate `host` presents expires. Raises when the handshake
    fails, a refused certificate included."""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT_SECONDS) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return expiry_of(tls.getpeercert())


def expiry_of(certificate: Mapping) -> datetime:
    """A certificate's notAfter, as `ssl` reports it, as a UTC time."""
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(certificate["notAfter"]), timezone.utc)


def clean(value: object, limit: int = 80) -> str:
    """Text a server or an exception supplied, safe for one log line: no control
    characters or line breaks (a line starting '::' is a workflow command), and
    short."""
    text = "".join(ch if ch.isprintable() else " " for ch in str(value))
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def status_words(code: int) -> str:
    try:
        return f"{code} {HTTPStatus(code).phrase}"
    except ValueError:
        return str(code)


def described(error: BaseException) -> str:
    """What a request that got no HTTP answer met, in words."""
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, TimeoutError):  # socket.timeout is TimeoutError from 3.10
        return f"no answer within {TIMEOUT_SECONDS} seconds"
    if isinstance(reason, ssl.SSLCertVerificationError):
        return f"its certificate was refused: {clean(getattr(reason, 'verify_message', None) or reason)}"
    if isinstance(reason, socket.gaierror):
        return "its name did not resolve"
    if isinstance(reason, ConnectionRefusedError):
        return "the connection was refused"
    if isinstance(reason, str):
        return f"no answer: {clean(reason)}"
    return f"no answer: {type(reason).__name__}: {clean(reason)}"


def json_fields(body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8"))
    except ValueError:  # UnicodeDecodeError is a ValueError too
        return {}
    return data if isinstance(data, dict) else {}


def health(name: str, url: str, get: Callable[[str], Answer], means: str) -> Result:
    """`/api/health` answers 200 with status "ok". Its 503 "degraded" means the
    database did not answer the app, and fails like no answer at all."""
    try:
        answer = get(url)
    except Exception as error:  # every way of not answering is a failure
        return Result(name, url, False, described(error), means)
    fields = json_fields(answer.body)
    status = fields.get("status")
    if answer.status == 200 and status == "ok":
        return Result(name, url, True, 'answered 200, status "ok"')
    saw = f"answered {status_words(answer.status)}"
    if status is not None:
        saw += f': status "{clean(status, 40)}"'
        if "database" in fields:
            saw += f', database "{clean(fields["database"], 40)}"'
    elif answer.status == 200:
        saw += ", not the health check's JSON"
    return Result(name, url, False, saw, means)


def home_page(url: str, get: Callable[[str], Answer]) -> Result:
    try:
        answer = get(url)
    except Exception as error:
        return Result("Home page", url, False, described(error), HOME_MEANS)
    if answer.status == 200:
        return Result("Home page", url, True, "answered 200")
    return Result("Home page", url, False, f"answered {status_words(answer.status)}", HOME_MEANS)


def host_of(url: str) -> str:
    """A web address's host, with its port unless it is HTTPS's own."""
    parts = urlsplit(url)
    return parts.hostname if parts.port in (None, 443) else f"{parts.hostname}:{parts.port}"


def pointed(url: str, location: str) -> str:
    """Where a redirect from `url` points, in words: a relative address as the
    full one it names, and one urllib can't read as it came."""
    location = location.strip()
    if not location:
        return "a redirect with no address"
    try:
        location = urljoin(url, location)
    except ValueError:
        pass
    return f"a redirect to {clean(location, 120)}"


def privacy_page(url: str, get: Callable[[str], Answer]) -> Result:
    """The owners' two checks on the privacy page the carrier cites: asked
    without following a redirect, it answers 200, and its HTML says "Privacy
    Policy". Named for its host, so a failure says which name it was."""
    name = f"Carrier-cited privacy page on {host_of(url)}"
    try:
        answer = get(url)
    except Exception as error:
        return Result(name, url, False, described(error), PRIVACY_MEANS)
    if answer.status == 200 and PRIVACY_PHRASE.encode() in answer.body:
        return Result(name, url, True, f'answered 200 with "{PRIVACY_PHRASE}" in its HTML')
    saw = f"answered {status_words(answer.status)}"
    if 300 <= answer.status < 400:
        saw += f", {pointed(url, answer.location)}, not the page itself"
    elif answer.status == 200:
        saw += f', without "{PRIVACY_PHRASE}" in its HTML'
    return Result(name, url, False, saw, PRIVACY_MEANS)


def certificate(host: str, port: int, now: datetime,
                expiry: Callable[[str, int], datetime]) -> Result:
    name = f"Certificate for {host}"
    target = host if port == 443 else f"{host}:{port}"
    try:
        expires = expiry(host, port)
    except Exception as error:
        refused = isinstance(getattr(error, "reason", error), ssl.SSLError)
        return Result(name, target, False, described(error),
                      CERTIFICATE_REFUSED_MEANS if refused else CERTIFICATE_UNREAD_MEANS)
    days = (expires - now) / timedelta(days=1)
    saw = f"{max(int(days), 0)} days left, expires {expires:%Y-%m-%d}"
    if days < CERTIFICATE_DAYS_MIN:
        return Result(name, target, False, saw, CERTIFICATE_LOW_MEANS)
    return Result(name, target, True, saw)


@dataclass(frozen=True)
class Config:
    """What to ask: the site, the tracking host when there is one, and the
    privacy page the carrier cites at each address given."""
    site_url: str
    tracking_url: str = ""
    privacy_urls: tuple[str, ...] = ()

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> "Config":
        site = web_address(env, "STATUS_CHECK_SITE_URL")
        if not site:
            raise ValueError("STATUS_CHECK_SITE_URL isn't set, so there is nothing to check.")
        return cls(site_url=site, tracking_url=web_address(env, "STATUS_CHECK_TRACKING_URL"),
                   privacy_urls=privacy_addresses(env))


def web_address(env: Mapping[str, str], name: str) -> str:
    value = (env.get(name) or "").strip().rstrip("/")
    if value:
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"{name} must be a web address starting https:// (it is {clean(value)!r}).")
    return value


def privacy_addresses(env: Mapping[str, str]) -> tuple[str, ...]:
    """STATUS_CHECK_PRIVACY_URLS: full https:// addresses, separated by spaces
    or commas, each once, in the order given. Blank is none."""
    urls: list[str] = []
    for url in (env.get(PRIVACY_URLS) or "").replace(",", " ").split():
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise ValueError(f"{PRIVACY_URLS} must be full web addresses starting https:// "
                             f"({clean(url)!r} is not one).")
        if url not in urls:
            urls.append(url)
    if len(urls) > PRIVACY_URLS_MAX:
        raise ValueError(f"{PRIVACY_URLS} names {len(urls)} addresses, and a run's report to "
                         f"the site has room for {PRIVACY_URLS_MAX}.")
    return tuple(urls)


def https_hosts(config: Config) -> list[tuple[str, int]]:
    """Each HTTPS host once, the site's first, then the tracking host's and
    the privacy pages'."""
    hosts: list[tuple[str, int]] = []
    for url in (config.site_url, config.tracking_url, *config.privacy_urls):
        parts = urlsplit(url)
        if url and parts.scheme == "https" and parts.hostname:
            host = (parts.hostname, parts.port or 443)
            if host not in hosts:
                hosts.append(host)
    return hosts


# --- the checker's memory: the workflow's earlier runs ------------------------

@dataclass(frozen=True)
class PastRun:
    """An earlier run of the workflow: when it started, whether it failed, and
    whether it got as far as asking the site (`judged`)."""
    at: datetime
    failed: bool
    judged: bool = True
    run_id: int | None = None


class HistoryUnavailable(Exception):
    """The workflow's earlier runs couldn't be read."""


PASSED = frozenset({"success"})
FAILED = frozenset({"failure", "timed_out"})


def parse_time(value: object) -> datetime | None:
    """GitHub's `2026-09-24T14:17:05Z`, on Python 3.10 too, which doesn't read the Z."""
    if not isinstance(value, str) or not value:
        return None
    try:
        at = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return at if at.tzinfo else at.replace(tzinfo=timezone.utc)


def runs_from(raw: Iterable[Mapping], current: str = "") -> list[PastRun]:
    """The runs that passed or failed, newest first. Skipped runs (the job's
    `if`) and cancelled ones asked nothing, and this run isn't history yet."""
    runs = []
    for run in raw:
        if not isinstance(run, Mapping):
            continue
        conclusion = run.get("conclusion")
        at = parse_time(run.get("created_at"))
        if str(run.get("id")) == current or conclusion not in PASSED | FAILED or at is None:
            continue
        runs.append(PastRun(at=at, failed=conclusion in FAILED, run_id=run.get("id")))
    return sorted(runs, key=lambda run: run.at, reverse=True)


def judged_failing(jobs: Mapping) -> bool:
    """Whether a failed run's check step failed: it asked the site and the site
    failed. One that failed earlier (a GitHub hiccup at checkout) judged nothing."""
    for job in jobs.get("jobs") or []:
        for step in job.get("steps") or []:
            if step.get("name") == CHECK_STEP:
                return step.get("conclusion") == "failure"
    return False


def github_api(url: str, token: str) -> dict:
    request = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    })
    with urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def api_trouble(error: BaseException) -> str:
    if isinstance(error, HTTPError):
        return f"GitHub's API answered {status_words(error.code)}"
    return described(error)


def past_runs(env: Mapping[str, str], io: "Io") -> tuple[list[PastRun], bool]:
    """This workflow's earlier completed runs on this branch, newest first, and
    whether they are all it has had. The failed runs at the head are looked
    into, until one that judged the site failing."""
    token, repo = env.get("GITHUB_TOKEN"), env.get("GITHUB_REPOSITORY")
    if not token or not repo:
        raise HistoryUnavailable("GITHUB_TOKEN and GITHUB_REPOSITORY are set only inside GitHub Actions")
    api = (env.get("GITHUB_API_URL") or "https://api.github.com").rstrip("/")
    branch = quote(env.get("GITHUB_REF_NAME") or "main", safe="")
    try:
        page = io.api(
            f"{api}/repos/{repo}/actions/workflows/{WORKFLOW_FILE}/runs?status=completed"
            f"&branch={branch}&exclude_pull_requests=true&per_page={HISTORY_RUNS}",
            token,
        )
        raw = list(page.get("workflow_runs") or [])
        whole = int(page.get("total_count") or 0) <= len(raw)
    except Exception as error:
        raise HistoryUnavailable(api_trouble(error)) from None

    runs = runs_from(raw, current=env.get("GITHUB_RUN_ID") or "")
    for index, run in enumerate(runs[:LOOK_INTO_AT_MOST]):
        if not run.failed:
            break
        try:
            jobs = io.api(f"{api}/repos/{repo}/actions/runs/{run.run_id}/jobs?filter=latest", token)
        except Exception:
            jobs = {}  # unreadable: it tells nothing either way
        if judged_failing(jobs):
            break
        runs[index] = replace(run, judged=False)
    return runs, whole


# --- the cadence ----------------------------------------------------------------

@dataclass(frozen=True)
class Decision:
    """Which email this run sends, if any, and since when the failure has lasted
    (`since_exact` is False when it began before the oldest run in sight)."""
    email: str | None
    since: datetime | None = None
    since_exact: bool = True


def marks(elapsed: timedelta) -> int:
    """How many four-hour marks a failure has passed, with the schedule's slack."""
    return (elapsed + SCHEDULE_SLACK) // REMIND_EVERY


def clock_block(at: datetime) -> int:
    return int(at.timestamp() // REMIND_EVERY.total_seconds())


def alert_due(failing: bool, now: datetime, past: Sequence[PastRun],
              whole_history: bool = True) -> Decision:
    """Whether this run emails, and which email: the whole cadence, with no I/O.

    - A failure that starts with this run: the failure email.
    - One that goes on: a reminder each time it passes another four hours since
      it began, not every hour.
    - A pass after a failure: one email saying so.

    `past` holds the earlier runs that passed or failed. A run that failed
    before it asked the site, while it is the latest, counts neither way. When
    every run in sight failed and more lie beyond (`whole_history` False), the
    failure's start is out of sight, and the reminders keep to the clock's
    four-hour marks (00:00, 04:00, ... UTC) instead.
    """
    runs = sorted(past, key=lambda run: run.at, reverse=True)
    while runs and runs[0].failed and not runs[0].judged:
        runs.pop(0)
    streak: list[PastRun] = []
    for run in runs:
        if not run.failed:
            break
        streak.append(run)
    if not streak:
        return Decision(FAILING, since=now) if failing else Decision(None)

    exact = len(streak) < len(runs) or whole_history
    began, last = streak[-1].at, streak[0].at
    if not failing:
        return Decision(PASSING_AGAIN, since=began, since_exact=exact)
    if exact:
        due = marks(now - began) > marks(last - began)
    else:
        due = clock_block(now) != clock_block(last)
    return Decision(STILL_FAILING if due else None, since=began, since_exact=exact)


# --- the email --------------------------------------------------------------------

@dataclass(frozen=True)
class Mail:
    """Where the alert goes, and the company SMTP server it goes through."""
    to: str
    host: str
    port: int
    username: str
    password: str = field(repr=False)
    sender: str

    def secrets(self) -> tuple[str, ...]:
        return (self.host, str(self.port), self.username, self.password, self.sender)


def mail_settings(env: Mapping[str, str]) -> tuple[Mail | None, list[str]]:
    """The alert's settings, or None and the names of those that aren't set."""
    missing = [name for name in (ALERT_TO, *SMTP_SECRETS) if not (env.get(name) or "").strip()]
    port = (env.get("STATUS_SMTP_PORT") or "").strip()
    if port and not port.isdigit():
        missing.append("STATUS_SMTP_PORT (a number)")
    if missing:
        return None, missing
    return Mail(
        to=env[ALERT_TO].strip(), host=env["STATUS_SMTP_HOST"].strip(), port=int(port),
        username=env["STATUS_SMTP_USERNAME"].strip(),
        password=env["STATUS_SMTP_PASSWORD"].rstrip("\r\n"),
        sender=env["STATUS_SMTP_FROM"].strip(),
    ), []


def clock_words(at: datetime) -> str:
    return f"{at:%H:%M} UTC on {at.day} {at:%B %Y}"


def duration_words(elapsed: timedelta) -> str:
    hours = elapsed / timedelta(hours=1)
    if hours < 1:
        return "under an hour"
    if hours < 47.5:
        count = round(hours)
        return f"about {count} hour{'' if count == 1 else 's'}"
    return f"about {round(hours / 24)} days"


def lasted(decision: Decision, now: datetime) -> str:
    since = decision.since or now
    if decision.since_exact:
        return f"since {clock_words(since)}, {duration_words(now - since)}"
    return (f"since before {clock_words(since)}, the oldest run still in sight: "
            f"more than {duration_words(now - since)}")


def compose(decision: Decision, *, site: str, results: Sequence[Result], now: datetime,
            run_url: str = "", note: str = "") -> tuple[str, str]:
    """The subject and plain-text body: what failed and what it saw first,
    because that is what the reader needs."""
    failed = [result for result in results if not result.ok]
    passed = [result for result in results if result.ok]
    if decision.email == PASSING_AGAIN:
        subject = "A&B website: passing its outside check again"
        lines = [
            f"{site} passes its outside check again, as of {clock_words(now)}.",
            f"It had been failing {lasted(decision, now)}.",
            "",
            "Every check passes:",
            *(f"- {result.name}, {result.target}: {result.saw}." for result in results),
        ]
    else:
        names = ", ".join(result.name for result in failed)
        if decision.email == FAILING:
            subject = f"A&B website: failing its outside check ({names})"
            lines = [f"{site} failed its outside check at {clock_words(now)}, twice, "
                     f"{RETRY_AFTER_SECONDS} seconds apart."]
        else:
            subject = f"A&B website: still failing its outside check ({names})"
            lines = [f"{site} is still failing its outside check at {clock_words(now)}.",
                     f"It has been failing {lasted(decision, now)}."]
        lines += ["", "What failed:"]
        for result in failed:
            lines += [f"- {result.name}, {result.target}: {result.saw}.", f"  {result.means}"]
        if passed:
            lines += ["", "What still passes:",
                      *(f"- {result.name}, {result.target}: {result.saw}." for result in passed)]
    lines += ["", "The checker runs every hour on GitHub, outside the server. It emails when "
                  "a failure starts, every four hours while it lasts, and once when it passes "
                  "again."]
    if note:
        lines.append(note)
    if run_url:
        lines += ["", f"This run: {run_url}"]
    return subject, "\n".join(lines) + "\n"


def message(mail: Mail, subject: str, body: str, now: datetime) -> EmailMessage:
    email = EmailMessage()
    email["From"] = mail.sender
    email["To"] = mail.to
    email["Subject"] = subject
    email["Date"] = format_datetime(now)
    domain = parseaddr(mail.sender)[1].rpartition("@")[2]
    email["Message-ID"] = make_msgid("status-check", domain=domain or "localhost")
    email["Auto-Submitted"] = "auto-generated"  # RFC 3834: nothing should auto-reply
    email.set_content(body)
    return email


def send(mail: Mail, email: EmailMessage, io: "Io") -> None:
    """Over the company SMTP server, never Mailgun: implicit TLS on port 465,
    STARTTLS on any other, and never a password in the clear."""
    context = ssl.create_default_context()
    if mail.port == 465:
        server = io.smtp_ssl(mail.host, mail.port, timeout=SMTP_TIMEOUT_SECONDS, context=context)
    else:
        server = io.smtp(mail.host, mail.port, timeout=SMTP_TIMEOUT_SECONDS)
    with server:
        if mail.port != 465:
            server.starttls(context=context)
        server.login(mail.username, mail.password)
        server.send_message(email)


def scrub(text: str, secrets: Iterable[str]) -> str:
    """`text` with every secret's value blanked. GitHub masks secrets in logs
    too; this doesn't rely on it."""
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "***")
    return text


# --- the run ----------------------------------------------------------------------

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def say(line: str) -> None:
    print(line, flush=True)


@dataclass
class Io:
    """Everything that reaches outside the process, so tests can stand in for it."""
    get: Callable[[str], Answer] = http_get
    get_no_redirects: Callable[[str], Answer] = http_get_no_redirects
    certificate: Callable[[str, int], datetime] = certificate_expiry
    api: Callable[[str, str], dict] = github_api
    smtp: Callable[..., smtplib.SMTP] = smtplib.SMTP
    smtp_ssl: Callable[..., smtplib.SMTP] = smtplib.SMTP_SSL
    post: Callable[[str, str, Mapping], Answer] = http_post
    sleep: Callable[[float], None] = time.sleep
    clock: Callable[[], datetime] = utc_now
    out: Callable[[str], None] = say


def annotation(level: str, title: str, text: str) -> str:
    """A workflow command, which the run's page shows as an annotation."""
    def data(value: str) -> str:
        return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    title = data(title).replace(":", "%3A").replace(",", "%2C")
    return f"::{level} title={title}::{data(text)}"


def attempt(config: Config, io: Io) -> list[Result]:
    """Every check, once."""
    site = config.site_url
    results = [
        health("API health", f"{site}/api/health", io.get, API_MEANS),
        home_page(f"{site}/", io.get),
    ]
    if config.tracking_url:
        results.append(health("Tracking host", f"{config.tracking_url}/api/health",
                              io.get, TRACKING_MEANS))
    results += [privacy_page(url, io.get_no_redirects) for url in config.privacy_urls]
    now = io.clock()
    results += [certificate(host, port, now, io.certificate) for host, port in https_hosts(config)]
    return results


def report(results: Sequence[Result], io: Io) -> None:
    width = max(len(result.name) for result in results)
    for result in results:
        mark = "ok  " if result.ok else "FAIL"
        io.out(f"  {mark}  {result.name.ljust(width)}  {result.target}: {result.saw}")


def run_url(env: Mapping[str, str]) -> str:
    server, repo, run = (env.get(name) for name in
                         ("GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID"))
    return f"{server}/{repo}/actions/runs/{run}" if server and repo and run else ""


def alert(config: Config, env: Mapping[str, str], io: Io, results: Sequence[Result],
          now: datetime) -> None:
    """Email if the cadence says so, and say plainly when nobody could be told."""
    failing = not all(result.ok for result in results)
    mail, missing = mail_settings(env)
    note = ""
    try:
        past, whole = past_runs(env, io)
    except HistoryUnavailable as error:
        io.out(annotation("warning", "Alert cadence",
                          f"Couldn't read this workflow's earlier runs ({error}), so a new "
                          "failure can't be told from one already emailed."))
        decision = Decision(FAILING, since=now) if failing else Decision(None)
        if failing:
            note = ("It couldn't read its own earlier runs this time, so it can't tell whether "
                    "this failure is new: until it can, it emails every hour the site fails.")
    else:
        decision = alert_due(failing, now, past, whole)

    if decision.email is None:
        if failing:
            io.out(f"No email this run: failing {lasted(decision, now)}, and a reminder "
                   "goes every four hours from its start.")
        else:
            io.out("No email: the site passes, and no failure needs an all-clear.")
        if missing:
            io.out(annotation("warning", "Alerts off",
                              f"Not set: {', '.join(missing)}. A failure would not be emailed "
                              "to anyone."))
        return

    level = "error" if failing else "warning"
    if mail is None:
        io.out(annotation(level, "Alert not emailed",
                          f"The {decision.email} email was not sent: {', '.join(missing)} "
                          "not set. Nobody has been told, except by this run's log."))
        return
    subject, body = compose(decision, site=config.site_url, results=results, now=now,
                            run_url=run_url(env), note=note)
    try:
        send(mail, message(mail, subject, body, now), io)
    except (smtplib.SMTPException, OSError) as error:
        trouble = clean(scrub(f"{type(error).__name__}: {error}", mail.secrets()), 200)
        io.out(annotation(level, "Alert not emailed",
                          f"Couldn't email the {decision.email} alert: {trouble}"))
        return
    io.out(f"Emailed the alert address: {subject}")


def report_payload(results: Sequence[Result], run: str) -> dict:
    """The run's result as the site's report route takes it: whether every
    check passed, each check's name, result and what it saw, and the run's
    page ("" for a run by hand)."""
    return {
        "passed": all(result.ok for result in results),
        "checks": [
            {"name": clean(result.name, REPORT_NAME_LIMIT), "ok": result.ok,
             "detail": clean(f"{result.target}: {result.saw}", REPORT_DETAIL_LIMIT)}
            for result in results
        ],
        "run_url": run,
    }


def report_back(config: Config, env: Mapping[str, str], io: Io,
                results: Sequence[Result]) -> None:
    """Tell the site's dashboard this run's result, when STATUS_CHECK_TOKEN is
    set. A report the site doesn't take is said plainly and fails nothing: the
    site checks decide the run, and a site that is down can't take it anyway."""
    token = (env.get(TOKEN) or "").strip()
    if not token:
        io.out(f"No {TOKEN}, so the dashboard isn't told this run's result.")
        return

    def warn(text: str) -> None:
        io.out(annotation("warning", "Dashboard report", clean(scrub(text, [token]), 400)))

    url = f"{config.site_url}{REPORT_PATH}"
    parts = urlsplit(url)
    if parts.scheme != "https" and parts.hostname not in LOOPBACK:
        warn(f"Not sent: the token only travels over HTTPS, and {url} is {parts.scheme}.")
        return
    try:
        answer = io.post(url, token, report_payload(results, run_url(env)))
    except Exception as error:  # every way of not answering is said the same way
        warn(f"The site didn't take this run's result: {described(error)}.")
        return
    if 200 <= answer.status < 300:
        io.out("The dashboard has this run's result.")
    elif answer.status == 401:
        warn(f"The site refused this run's result (401): the token in Settings -> Monitoring "
             f"and the secret {TOKEN} differ, or none was made there. Make a new token "
             "there and save it as the secret.")
    else:
        detail = json_fields(answer.body).get("detail")
        why = f": {detail}" if isinstance(detail, str) and detail else ""
        if 300 <= answer.status < 400:
            why += (" (the report doesn't follow redirects: set STATUS_CHECK_SITE_URL to "
                    "the address the site sends it to)")
        warn(f"The site didn't take this run's result: answered "
             f"{status_words(answer.status)}{why}.")


def main(env: Mapping[str, str] | None = None, io: Io | None = None) -> int:
    env = os.environ if env is None else env
    io = io or Io()
    try:
        config = Config.from_env(env)
    except ValueError as error:
        io.out(annotation("error", "Status check", str(error)))
        return 2

    started = io.clock()
    io.out(f"Checking {config.site_url} from outside, at {clock_words(started)}.")
    results = attempt(config, io)
    report(results, io)
    retried = not all(result.ok for result in results)
    if retried:
        io.out(f"Something failed. One slow answer is not an incident: asking everything "
               f"again in {RETRY_AFTER_SECONDS} seconds.")
        io.sleep(RETRY_AFTER_SECONDS)
        results = attempt(config, io)
        report(results, io)

    failed = [result for result in results if not result.ok]
    for result in failed:
        io.out(annotation("error", result.name, f"{result.target}: {result.saw}"))
    if failed:
        io.out(f"The site failed twice, {RETRY_AFTER_SECONDS} seconds apart, so this run fails.")
    elif retried:
        io.out("The second attempt passed: not an incident.")
    else:
        io.out("Every check passed.")
    report_back(config, env, io, results)
    alert(config, env, io, results, started)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
