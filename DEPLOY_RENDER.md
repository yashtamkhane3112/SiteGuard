# SiteGuard Render Deployment

SiteGuard is configured for a simple free-tier Render deployment:

- Django web service
- SQLite
- WhiteNoise for static files
- Render Cron Job
- Existing `monitor_sites` workflow

## 1. Required Environment Variables

Set these on the Render web service and cron job:

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY=<long random secret>`
- `ALLOWED_HOSTS=<your-render-host>`
- `CSRF_TRUSTED_ORIGINS=https://<your-render-host>`
- `APP_BASE_URL=https://<your-render-host>`
- `CRON_SECRET=<random secret used by the cron trigger>`

If email alerts should work, also set:

- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_USE_TLS`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`
- `DEFAULT_FROM_EMAIL`

Recommended production values:

- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`

## 2. Render Setup

1. Create a new Blueprint deployment from this repository.
2. Render will read [`render.yaml`](/E:/Testing%20django%202/Testing/siteguard/render.yaml).
3. Set the required environment variables in the Render dashboard.
4. Deploy the web service.
5. Deploy the cron job after the web service is live.

## 3. Build and Startup

Web service:

- Build command: `pip install -r requirements.txt && python manage.py collectstatic --noinput && python manage.py migrate --noinput`
- Start command: `gunicorn siteguard.wsgi:application`

Cron job:

- Schedule: `*/5 * * * *`
- Start command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

## 4. Why the Cron Uses HTTP

Render free cron and web services do not share the same local SQLite file.

To keep SQLite and stay on free infrastructure, the cron job calls the web app's protected internal monitoring endpoint, which runs the existing `monitor_sites` command inside the web service environment. This keeps monitoring state, incidents, alerts, and logs in the same SQLite database used by the app.

## 5. SQLite Notes

- Production defaults to `/tmp/siteguard.sqlite3` on Render.
- This path is writable on free Render instances.
- SQLite data on free Render remains ephemeral and can be lost on restart/redeploy.

This is acceptable for internship, demo, and portfolio usage, but it is not durable production storage.

## 6. Collectstatic Notes

- WhiteNoise serves files from `staticfiles/`
- `collectstatic` runs during the build step
- Static CSS, JS, and images are available without an external storage service

## 7. Monitoring Recommendation

- Recommended frequency: every 5 minutes
- Command preserved: `python manage.py monitor_sites`
- Render-safe trigger: cron hits the protected internal endpoint, which executes the command in the web service

## 8. Local Production Check

Useful commands:

```bash
python manage.py check --deploy --settings=siteguard.settings.prod
python manage.py collectstatic --noinput --settings=siteguard.settings.prod
python manage.py migrate --settings=siteguard.settings.prod
python manage.py monitor_sites --settings=siteguard.settings.prod
```
