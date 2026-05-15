# SiteGuard Render Deployment

## Overview

SiteGuard runs on Render free tier with:

- one Django web service
- one Render cron job
- SQLite
- WhiteNoise
- Gunicorn
- Python 3.12.3

## Required Environment Variables

Set these on the Render web service and cron job:

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY=<strong random secret>`
- `ALLOWED_HOSTS=<render-hostname>`
- `CSRF_TRUSTED_ORIGINS=https://<render-hostname>`
- `APP_BASE_URL=https://<render-hostname>`
- `CRON_SECRET=<long random secret>`
- `EMAIL_HOST=<smtp host>`
- `EMAIL_PORT=<smtp port>`
- `EMAIL_HOST_USER=<smtp username>`
- `EMAIL_HOST_PASSWORD=<smtp password>`
- `DEFAULT_FROM_EMAIL=SiteGuard Alerts <noreply@your-domain>`

Recommended:

- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`
- `LOG_LEVEL=INFO`
- `DJANGO_LOG_LEVEL=INFO`
- `EMAIL_TIMEOUT=15`
- `EMAIL_USE_TLS=True`
- `EMAIL_USE_SSL=False`
- `SERVER_EMAIL=SiteGuard Alerts <noreply@your-domain>`
- `SUPPORT_EMAIL=support@your-domain`
- `EMAIL_SENDER_NAME=SiteGuard Alerts`
- `EMAIL_SUBJECT_PREFIX=[SiteGuard] `
- `SITE_NAME=SiteGuard`

Optional email settings:

- `EMAIL_BACKEND`

## Render Service Configuration

Python runtime alignment:

- Render is pinned to Python `3.12.3`
- Local development should also use Python `3.12.3`
- Do not validate Django admin behavior on Python `3.14` while the project remains on Django `5.0.4`

Web service:

- Build command: `pip install -r requirements.txt`
- Start command: `bash ./start.sh`

Cron job:

- Schedule: `*/5 * * * *`
- Start command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

Do not override the web start command with `gunicorn siteguard.wsgi:application`. That bypasses startup migrations.

## Startup Sequence

[`start.sh`](/E:/Testing%20django%202/Testing/siteguard/start.sh:1) performs:

1. export production settings
2. run migrations
3. verify `auth_user`
4. collect static files
5. start Gunicorn

The script exits on the first error.

## Why the Cron Uses HTTP

Render free cron and web services do not share the same local SQLite file. The cron therefore calls the protected internal endpoint on the web service, which executes `monitor_sites` inside the same runtime environment as the application database.

## SQLite Notes

- Production defaults to `data/siteguard.sqlite3`
- Render free tier storage remains ephemeral
- Data can be lost on restart or redeploy
- Startup migrations are mandatory every boot

## Health Check

Use:

- `/health/`

Expected output includes:

```json
{
  "status": "ok",
  "database": true,
  "auth_user_table": true
}
```

## Deployment Verification

Confirm these log lines:

- `STARTUP SCRIPT RUNNING`
- `Running migrations...`
- `Checking auth table...`
- `('auth_user',)`
- `Collecting static...`
- `Starting gunicorn...`

Then verify:

- homepage GET
- signup GET and POST
- login GET and POST
- `/health/`
- password reset request creates an email with `https://<render-hostname>/reset/...`
- alert retry sends a real operational email from the configured sender identity

## Local Production Checks

Before running these checks locally, verify:

```bash
python --version
```

Expected:

```text
Python 3.12.3
```

```bash
python manage.py check --deploy --settings=siteguard.settings.prod
python manage.py migrate --settings=siteguard.settings.prod --noinput
python manage.py collectstatic --settings=siteguard.settings.prod --noinput
python manage.py monitor_sites --settings=siteguard.settings.prod
python manage.py test_email your@email.com --kind operational --settings=siteguard.settings.prod
```
