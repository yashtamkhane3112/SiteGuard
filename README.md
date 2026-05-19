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

Use Python `3.12.3` locally to match Render production.

Do not use Python `3.14` with this repository while it is pinned to Django `5.0.4`. Django `5.0` officially supports Python `3.10`, `3.11`, and `3.12`, not `3.14`.

```bash
py -3.12 -m venv .venv
.\.venv\Scripts\activate
python --version
pip install --upgrade pip
pip install -r requirements.txt
copy .env.example .env
python manage.py migrate
python manage.py runserver
```

For real local email delivery, set `RESEND_API_KEY`, `DEFAULT_FROM_EMAIL`, and optionally `SERVER_EMAIL` in `.env`. SiteGuard now sends mail through Resend only, using `django-anymail`.

Resend local setup:

1. Create a Resend API key with sending access.
2. Verify the sender domain or use an approved Resend test sender while validating setup.
3. Set `RESEND_API_KEY` in `.env`.
4. Set `DEFAULT_FROM_EMAIL` and `SERVER_EMAIL` to the sender identity you want Resend to use.
5. Local password reset emails use the active request host while `DEBUG=True`, so start the app on the exact host you want in the email, such as `http://127.0.0.1:8000` or `http://localhost:8000`.
6. Keep `APP_BASE_URL` pointed at your production HTTPS origin for Render production mail.

Local email verification:

```bash
python manage.py test_email your@email.com
python manage.py test_email your@email.com --kind operational --site https://example.com
python manage.py test_email your@email.com --kind password_reset
```

If `python --version` still prints `Python 3.14.x`, you are not using the project virtual environment. In that case run commands explicitly through the venv:

```bash
.\.venv\Scripts\python.exe --version
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py runserver
```

If you already created a virtual environment with Python `3.14`, remove it and recreate it on Python `3.12.3`:

```bash
deactivate
Remove-Item -Recurse -Force .venv
py -3.12 -m venv .venv
.\.venv\Scripts\activate
python --version
pip install --upgrade pip
pip install -r requirements.txt
```

`Pillow` is required because profile avatar uploads use Django image validation. Do not remove it from `requirements.txt`, and do not rely on a global Python installation for image support.

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
- Resend mail variables: `RESEND_API_KEY`, `DEFAULT_FROM_EMAIL`
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
- Render production already uses Python `3.12.3`, which is the correct stable target for this Django version
