# SiteGuard Render Deployment

## Overview

SiteGuard runs on Render free tier with:

- one Django web service
- one Render cron job
- PostgreSQL for production data
- signed-cookie sessions temporarily retained during the migration phase
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
- `DATABASE_URL=<Render internal PostgreSQL URL>`
- `EMAIL_BACKEND=brevo_api`
- `BREVO_API_KEY=<brevo api key>`
- `BREVO_API_URL=https://api.brevo.com/v3/smtp/email`
- `DEFAULT_FROM_EMAIL=SiteGuard Alerts <noreply@your-domain>`
- `CLOUDINARY_CLOUD_NAME=<cloud name>`
- `CLOUDINARY_API_KEY=<api key>`
- `CLOUDINARY_API_SECRET=<api secret>`

Recommended:

- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`
- `DJANGO_BOOTSTRAP_ADMIN=False`
- `LOG_LEVEL=INFO`
- `DJANGO_LOG_LEVEL=INFO`
- `EMAIL_TIMEOUT=15`
- `SERVER_EMAIL=SiteGuard Alerts <noreply@your-domain>`
- `SUPPORT_EMAIL=support@your-domain`
- `EMAIL_SENDER_NAME=SiteGuard Alerts`
- `EMAIL_SUBJECT_PREFIX=[SiteGuard] `
- `SITE_NAME=SiteGuard`
- `AI_FEATURES_ENABLED=False`
- `AI_PROVIDER=gemini`
- `GEMINI_MODEL=gemini-1.5-flash`
- `AI_REQUEST_TIMEOUT=20`
- `AI_MAX_TOKENS=900`
- `AI_RETRY_ATTEMPTS=2`
- `AI_RETRY_BACKOFF_SECONDS=0.5`

Optional AI operational intelligence on the web service only:

- `AI_FEATURES_ENABLED=True`
- `GEMINI_API_KEY=<google ai studio api key>`

Gemini support is installed through the official `google-generativeai` Python SDK in `requirements.txt`. The web service initializes it with `GEMINI_API_KEY` and creates the configured `GEMINI_MODEL`, which defaults to `gemini-1.5-flash`.
Startup logs include AI diagnostics for the resolved provider, resolved Gemini model, and whether the Gemini API key is present. Use `python manage.py test_ai_provider --settings=siteguard.settings.prod` on the web service to validate the active runtime configuration.

OpenAI remains available as a non-default provider by setting:

- `AI_PROVIDER=openai`
- `OPENAI_API_KEY=<openai api key>`
- `OPENAI_MODEL=<openai model>`

Do not add AI provider credentials to the monitor cron job unless a future command explicitly needs them. Monitoring must remain independent from AI generation.

## Render Service Configuration

Python runtime alignment:

- Render is pinned to Python `3.12.3`
- Local development should also use Python `3.12.3`
- Do not validate Django admin behavior on Python `3.14` while the project remains on Django `5.0.4`

Web service:

- Build command: `pip install -r requirements.txt`
- Start command: `bash ./start.sh`
- `DATABASE_URL` should be set on the web service to the Render internal PostgreSQL URL
- Keep `SESSION_ENGINE=django.contrib.sessions.backends.signed_cookies` for now

Optional one-time admin bootstrap on the web service only:

- `DJANGO_BOOTSTRAP_ADMIN=True`
- `DJANGO_ADMIN_USERNAME=<admin username>`
- `DJANGO_ADMIN_EMAIL=<admin email>`
- `DJANGO_ADMIN_PASSWORD=<strong admin password>`

After the deploy succeeds and the superuser is confirmed, set:

- `DJANGO_BOOTSTRAP_ADMIN=False`

Cron job:

- Schedule: `*/5 * * * *`
- Start command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

Do not override the web start command with `gunicorn siteguard.wsgi:application`. That bypasses startup migrations.

## Startup Sequence

[`start.sh`](/E:/Testing%20django%202/Testing/siteguard/start.sh:1) performs:

1. export production settings
2. run migrations
3. optionally run `python manage.py bootstrap_admin` only when `DJANGO_BOOTSTRAP_ADMIN=True`
4. run a database connectivity probe, verify `auth_user`, and verify `django_session` only when DB-backed sessions are enabled
5. collect static files
6. start Gunicorn

The script exits on the first error.

## Admin Bootstrap Command

Use:

```bash
python manage.py bootstrap_admin --settings=siteguard.settings.prod
```

Required environment variables:

- `DJANGO_ADMIN_USERNAME`
- `DJANGO_ADMIN_EMAIL`
- `DJANGO_ADMIN_PASSWORD`

Behavior:

- creates the configured user if missing
- updates the configured user if it already exists
- enforces `is_staff=True`, `is_superuser=True`, and `is_active=True`
- never prints the password
- fails clearly if required environment variables are missing
- is idempotent and safe to rerun

Expected startup log lines when using the deploy/start integration:

- `Admin bootstrap executed: running bootstrap_admin...`
- `Admin bootstrap success.`
- `Admin bootstrap skipped.`
- `Admin bootstrap failure.`

## Why the Cron Uses HTTP

Render free cron and web services do not share the same local SQLite file. The cron therefore calls the protected internal endpoint on the web service, which executes `monitor_sites` inside the same runtime environment as the application database.

## Database Notes

- Local development still defaults to SQLite
- Production uses `DATABASE_URL` when present
- If `DATABASE_URL` is absent, production falls back to `data/siteguard.sqlite3`
- Startup logs now emit database diagnostics for engine, host, database name, SSL mode, and connection health
- Startup migrations remain mandatory every boot

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
- `Checking database readiness...`
- `Collecting static...`
- `Starting gunicorn...`

Then verify:

- homepage GET
- signup GET and POST
- login GET and POST
- `/health/`
- password reset request creates an email with `https://<render-hostname>/reset/...`
- alert retry sends a real operational email through the configured Brevo API sender identity

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

## PostgreSQL Cutover Steps

1. Confirm the Render web service has `DATABASE_URL` set to the internal PostgreSQL URL.
2. Confirm `SESSION_ENGINE=django.contrib.sessions.backends.signed_cookies` remains set on the web service.
3. Deploy the `postgres-migration` branch.
4. Watch startup logs for:
   - `Database startup diagnostics:`
   - `connection_health=healthy`
   - `Running migrations...`
   - `Checking database readiness...`
5. Open `/health/` and confirm `status: ok`.
6. Verify signup, login, monitoring, Cloudinary upload, password reset, and operations dashboard flows.
7. Keep signed-cookie sessions in place until PostgreSQL runtime stability is confirmed, then switch `SESSION_ENGINE` back to `django.contrib.sessions.backends.db` in a later deployment.
