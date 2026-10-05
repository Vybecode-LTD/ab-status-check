# ab-status-check

The outside status checker for the Ashford & Briggs website. Every five minutes,
from GitHub's runners, it asks whether the site answers: its `/api/health`, its home
page, the tracking host once there is one, the privacy page the carrier cites on both
of the company's names, and each certificate's days left. When a check fails twice in
a row, 90 seconds apart, it emails an alert over the company mail server, repeats every
four hours while the problem lasts, and sends an all-clear once the site has passed
again for 30 minutes; a failure inside that half hour is the same incident. It also
reports each run to the site's admin dashboard.

The script is a copy of `scripts/status_check.py` in the website's repository, where it
is tested; change it there and copy it here. It uses Python's standard library only.

## What starts it

[cron-job.org](https://cron-job.org) starts the workflow every five minutes through
`workflow_dispatch`: a `POST` to
`https://api.github.com/repos/Vybecode-LTD/ab-status-check/actions/workflows/status-check.yml/dispatches`
with the body `{"ref":"main"}`. Its token is a fine-grained personal access token with
access to this repository only and one permission, *Actions: Read and write*, so it can
start, cancel or delete runs here and nothing else: no secrets, no code, no runners. It
expires after a year; GitHub emails before it does, and cron-job.org emails when its
requests start failing.

GitHub's own schedule, every five minutes in `status-check.yml`, stays as a backstop.
On its own it ran the workflow only 2.5 to 7.8 hours apart, because GitHub delays
scheduled runs under load and drops some. The workflow's `concurrency` group keeps a
dispatched run and a scheduled one from overlapping.

## Settings

Repository **variables**:

| Name | What |
|---|---|
| `STATUS_CHECK_SITE_URL` | The site's address, for example `https://example.com`. The check is skipped until it is set |
| `STATUS_CHECK_TRACKING_URL` | Optional: the tracking host's address |
| `STATUS_ALERT_TO` | Where alerts go |

Repository **secrets**:

| Name | What |
|---|---|
| `STATUS_SMTP_HOST`, `STATUS_SMTP_PORT` | The mail server. Port 465 is implicit TLS; any other port uses STARTTLS |
| `STATUS_SMTP_USERNAME`, `STATUS_SMTP_PASSWORD` | Its sign-in: an alerts mailbox's app password |
| `STATUS_SMTP_FROM` | The alerts' From address |
| `STATUS_CHECK_TOKEN` | The token made on the site's Settings → Monitoring |

`keepalive.yml` pushes an empty commit once a month, because GitHub turns off a public
repository's schedules after 60 days without activity.
