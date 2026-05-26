# Repository Guidelines

## Project Structure
`siteguard/` contains Django 5 project settings, URL wiring, and WSGI/ASGI entrypoints. `monitor/` is the core app for website checks, incidents, alerts, notifications, email delivery, AI analysis, and management commands. Templates live in `templates/`, static assets in `static/`, and tests are currently concentrated in `monitor/tests.py`. Runtime output directories such as `media/`, `staticfiles/`, and `data/` are not source files.

## Development Commands
Use Python 3.12 and the repo-local virtualenv.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
.\.venv\Scripts\python.exe manage.py monitor_sites
.\.venv\Scripts\python.exe manage.py test_email you@example.com --kind operational --site https://example.com
```

Production runs on Render with Neon PostgreSQL, DB-backed sessions, Cloudinary media plus raw analyzer uploads, Brevo transactional email, and Gemini operational intelligence. SQLite is local-only.

## Testing and Deployment Validation
Run the full regression suite before shipping monitoring, alert, session, email, storage, or settings changes.

```powershell
.\.venv\Scripts\python.exe manage.py test
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py migrate --settings=siteguard.settings.prod --noinput
.\.venv\Scripts\python.exe manage.py check --deploy --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py collectstatic --noinput --settings=siteguard.settings.prod
```

## Branching and Commits
Work branch-first. Never commit directly to `main`; create or continue a feature/fix branch and open a PR. Recent history uses short imperative subjects such as `Persist alerts before sending operational emails` and `Make initial down alerts explicit`.

## Monitoring Lifecycle Expectations
Keep state handling explicit: `UNKNOWN`, `UP`, `DOWN`, `SLOW`, `RECOVERY`, and `SSL_FAILURE`. Persist monitor logs before transition evaluation. Preserve `transaction.on_commit` behavior so alert rows exist before notifications or operational emails fire. Do not break dedup, cooldown, recovery, SSL, or repeated-DOWN suppression paths.

## Production Safety Rules
Treat production tracing as part of the feature. Keep structured logging and diagnostics intact for monitoring transitions, email dispatch, storage, sessions, and deploy validation. Validate changes against Neon/PostgreSQL behavior, not only SQLite.

## Environment and Debugging Expectations
Do not commit secrets. Start from `.env.example`; production validation requires correct values for `APP_BASE_URL`, `CRON_SECRET`, secret keys, Brevo settings, Cloudinary settings, and `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`. When debugging, include the exact command run, the affected path, and whether the issue reproduces on the full test suite.
