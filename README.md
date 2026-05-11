# SiteGuard

SiteGuard is a Django SaaS project for monitoring websites, tracking uptime and incidents, and surfacing alerts, notifications, and account-scoped operational history.

## Screenshots

Add production screenshots before publishing:

- `docs/screenshots/homepage.png`
- `docs/screenshots/dashboard.png`
- `docs/screenshots/incidents.png`
- `docs/screenshots/alerts.png`

## Features

- account signup, login, logout, and profile management
- per-user website monitoring
- uptime, latency, and slow-response tracking
- incidents, alerts, and notifications
- search and utilities
- Render-safe startup with enforced migrations
- WhiteNoise static serving
- cron-triggered monitoring within the web runtime
- health endpoint for operational verification

## Tech Stack

- Python 3.12
- Django 5
- SQLite
- Gunicorn
- WhiteNoise
- Render

## Local Setup

```bash
python -m venv .venv
. .venv/Scripts/activate
pip install -r requirements.txt
copy .env.example .env
python manage.py migrate
python manage.py runserver
```

Local production checks:

```bash
python manage.py migrate --settings=siteguard.settings.prod --noinput
python manage.py collectstatic --settings=siteguard.settings.prod --noinput
python manage.py check --deploy --settings=siteguard.settings.prod
```

## Render Deployment

- Build command: `pip install -r requirements.txt`
- Start command: `bash ./start.sh`

See [DEPLOY_RENDER.md](/E:/Testing%20django%202/Testing/siteguard/DEPLOY_RENDER.md:1) and [DEPLOY_CHECKLIST.md](/E:/Testing%20django%202/Testing/siteguard/DEPLOY_CHECKLIST.md:1).

## Environment Variables

Required production variables:

- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`

See [ENVIRONMENT_VARIABLES.md](/E:/Testing%20django%202/Testing/siteguard/ENVIRONMENT_VARIABLES.md:1) for the full list.

## Startup Flow

The production startup sequence is:

1. export `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
2. run migrations
3. verify `auth_user` exists
4. collect static files
5. start Gunicorn

## Monitoring Architecture

- the web service owns the active SQLite database
- the cron service does not write directly to SQLite
- cron calls `/internal/run-monitoring/<CRON_SECRET>/`
- the web app runs `monitor_sites` inside the same runtime

## Future Roadmap

- PostgreSQL support
- durable backups
- stronger auth and full 2FA
- richer logging and audit trails
- API-ready service boundaries
- expanded CI/CD

## Production Notes

- Render free tier storage is ephemeral
- migrations must run during startup
- `/health/` provides a basic app and database check
- keep `BOOTSTRAP_ADMIN_ENABLED=False` in production
