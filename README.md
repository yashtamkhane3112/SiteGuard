# SiteGuard

SiteGuard is a Django 5 monitoring platform for website uptime, incident management, operational alerts, notifications, and AI-assisted troubleshooting. Production runs on Render with Neon PostgreSQL, database-backed sessions, Cloudinary media storage, Brevo transactional email, and optional Gemini operational intelligence.

## Production Stack

- Django 5 on Python 3.12
- Render web service plus Render cron trigger
- Neon PostgreSQL in production
- SQLite only for local development
- Django DB-backed sessions
- Cloudinary media storage and raw analyzer uploads
- Brevo transactional email
- Gemini AI for optional report, incident, and error analysis

## Core Lifecycle

1. `monitor_sites` or `check_now` runs a monitoring check.
2. A `MonitorLog` row is persisted first.
3. Incident state transitions evaluate `UNKNOWN`, `UP`, `DOWN`, `SLOW`, `RECOVERY`, and `SSL_FAILURE`.
4. New alert rows are persisted before notifications or operational email dispatch.
5. `transaction.on_commit` creates notifications and sends operational email only after the alert row is durable.

The first `UNKNOWN -> DOWN` transition now creates the full lifecycle on PostgreSQL: incident, alert, notification, and email.

## Local Development

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
```

Local development defaults to SQLite and console email unless you explicitly configure Brevo or SMTP values in `.env`.

## Validation Commands

```powershell
.\.venv\Scripts\python.exe manage.py test
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py check --deploy --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py collectstatic --dry-run --noinput --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py showmigrations monitor --settings=siteguard.settings.prod
```

## Documentation

- [DEPLOYMENT.md](DEPLOYMENT.md)
- [ENVIRONMENT_SETUP.md](ENVIRONMENT_SETUP.md)
- [ARCHITECTURE.md](ARCHITECTURE.md)
- [ALERT_LIFECYCLE.md](ALERT_LIFECYCLE.md)
- [BRANCH_HISTORY.md](BRANCH_HISTORY.md)
- [PRODUCTION_CHECKLIST.md](PRODUCTION_CHECKLIST.md)
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
- [AGENTS.md](AGENTS.md)

## Operational Notes

- Keep `start.sh` as the Render web start command so migrations, admin bootstrap checks, and static collection run consistently.
- Keep `DATABASE_URL` pointed at Neon in production.
- Keep `SESSION_ENGINE=django.contrib.sessions.backends.db` in production.
- Keep `MONITOR_ALERT_ON_INITIAL_DOWN=True` unless you intentionally want first-down suppression.
- Startup diagnostics are safe for Django initialization and defer DB/session probing until a real connection exists.
