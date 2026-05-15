# Environment Variables

## Required in Production

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`
- `DEFAULT_FROM_EMAIL`

## Optional

- `EMAIL_BACKEND`
- `EMAIL_USE_TLS`
- `EMAIL_USE_SSL`
- `EMAIL_TIMEOUT`
- `SERVER_EMAIL`
- `SUPPORT_EMAIL`
- `EMAIL_SENDER_NAME`
- `SQLITE_PATH`
- `SQLITE_TIMEOUT`
- `SITE_NAME`
- `EMAIL_SUBJECT_PREFIX`
- `LOG_LEVEL`
- `DJANGO_LOG_LEVEL`
- `WHITENOISE_MAX_AGE`

Default production SQLite path is `data/siteguard.sqlite3` unless `SQLITE_PATH` is explicitly set.

Notes:

- `APP_BASE_URL` must be a valid HTTPS URL in production because password reset emails and operational links are generated from it.
- Local development auto-selects `django.core.mail.backends.smtp.EmailBackend` when `EMAIL_HOST_USER` and `EMAIL_HOST_PASSWORD` are present. If either credential is missing, it falls back to `django.core.mail.backends.console.EmailBackend`.
- You can still force a specific backend by setting `EMAIL_BACKEND` explicitly.
- Password reset emails use the active local request host during `DEBUG=True` development flows, so local forgot-password links stay on `127.0.0.1`, `localhost`, or the host you are actively using.
- Production password reset and operational email links use `APP_BASE_URL` / `CANONICAL_BASE_URL`, which must stay HTTPS on Render.

## Local Gmail SMTP Setup

For real local mail delivery with Gmail:

1. Enable 2-Step Verification on the Gmail account you want to send from.
2. Create a Google App Password for `Mail`.
3. Copy `.env.example` to `.env`.
4. Set:
   - `EMAIL_HOST=smtp.gmail.com`
   - `EMAIL_PORT=587`
   - `EMAIL_USE_TLS=True`
   - `EMAIL_HOST_USER=<your gmail address>`
   - `EMAIL_HOST_PASSWORD=<your 16-character app password>`
   - `DEFAULT_FROM_EMAIL=SiteGuard Alerts <your gmail address>`
   - `SERVER_EMAIL=SiteGuard Alerts <your gmail address>`
   - `SUPPORT_EMAIL=<your gmail address>`
5. Leave `EMAIL_BACKEND` blank unless you need to force a backend manually.
6. For local forgot-password testing, open the site on the exact host you want reflected in the email link, such as `http://127.0.0.1:8000` or `http://localhost:8000`.

Useful verification commands:

```bash
python manage.py test_email your@email.com
python manage.py test_email your@email.com --kind operational --site https://example.com
python manage.py test_email your@email.com --kind password_reset
```

## Reference

Use [.env.example](/E:/Testing%20django%202/Testing/siteguard/.env.example:1) as the starting template.
