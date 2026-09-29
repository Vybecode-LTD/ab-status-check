# ab-status-check

The outside status checker for the Ashford & Briggs website. Every five minutes,
from GitHub's runners, it asks whether the site answers: its `/api/health`, its home
page, the tracking host once there is one, and each certificate's days left. When a
check fails twice in a row it emails an alert over the company mail server, repeats
every four hours while the problem lasts, and sends an all-clear when it passes again.
It also reports each run to the site's admin dashboard.

The script is a copy of `scripts/status_check.py` in the website's repository, where it
is tested; change it there and copy it here. It uses Python's standard library only.

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
