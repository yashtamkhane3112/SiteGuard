# Production Checklist

## Before Deploy

- `main` is clean
- `DATABASE_URL` points to Neon
- `APP_BASE_URL` matches the Render web origin
- `CRON_SECRET` is configured on both web and cron services
- Brevo and Cloudinary credentials are present

## Validation Commands

```powershell
.\.venv\Scripts\python.exe manage.py test
.\.venv\Scripts\python.exe manage.py check --deploy --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py collectstatic --dry-run --noinput --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py showmigrations monitor --settings=siteguard.settings.prod
```

## Post-Deploy Checks

- `/health/` returns healthy status
- signup and login work
- sessions persist across refresh
- adding a fresh DOWN website creates incident, alert, notification, and operational email
- `/alerts/` shows the new alert
- recovery flow creates recovery alert

## Operational Checks

- Render web service starts through `start.sh`
- Render cron hits the protected monitoring endpoint
- Brevo delivery logs are clean
- Cloudinary uploads succeed
- startup logs do not emit Django’s app-initialization DB RuntimeWarning
