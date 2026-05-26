# Troubleshooting

## Startup Fails on Render

- Confirm the start command is `bash ./start.sh`.
- Confirm `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`.
- Confirm `SECRET_KEY`, `APP_BASE_URL`, `ALLOWED_HOSTS`, and `CRON_SECRET` are present.

## Database Problems

- Production must use Neon via `DATABASE_URL`.
- Local development should stay on SQLite unless you intentionally validate against PostgreSQL.
- If alerts work locally but not in production, inspect monitoring traces around incident creation and `alert_on_commit_callback_fired`.

## Alerts Not Appearing

Check, in order:

1. `MonitorLog` row exists
2. `Incident` row exists
3. `Alert` row exists in `monitor_alert`
4. `Notification` row exists
5. `/alerts/` renders the alert for the correct user

The major production bug was a PostgreSQL-sensitive new-incident gate. That has been fixed by explicit lifecycle tracking rather than timestamp equality.

## Email Problems

- Password reset and operational alert emails share the same final transport layer.
- Validate Brevo with `python manage.py test_email you@example.com`.
- Confirm `DEFAULT_FROM_EMAIL`, `SERVER_EMAIL`, and `BREVO_API_KEY` are valid.

## Media Problems

- Cloudinary is required in production.
- Analyzer uploads use raw Cloudinary storage.
- Missing avatars or upload failures usually indicate missing Cloudinary credentials or an incorrect storage backend.

## Startup Warning

If you ever see `Accessing the database during app initialization is discouraged`, re-check `monitor/apps.py`. `AppConfig.ready()` must not execute ORM queries, cursor probes, or table introspection.
