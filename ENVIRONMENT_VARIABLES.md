# Environment Variables

## Required in Production

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `BREVO_API_KEY`
- `DEFAULT_FROM_EMAIL`

## Optional

- `EMAIL_BACKEND`
- `EMAIL_TIMEOUT`
- `BREVO_API_URL`
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
- Local development auto-selects the Brevo Transactional Email HTTPS API when `BREVO_API_KEY` is present. If the API key is missing, it falls back to `django.core.mail.backends.console.EmailBackend`.
- You can still force a specific backend by setting `EMAIL_BACKEND` explicitly.
- Password reset emails use the active local request host during `DEBUG=True` development flows, so local forgot-password links stay on `127.0.0.1`, `localhost`, or the host you are actively using.
- Production password reset and operational email links use `APP_BASE_URL` / `CANONICAL_BASE_URL`, which must stay HTTPS on Render.

## Local Brevo API Setup

For real local mail delivery with the Brevo Transactional Email API:

1. Create a Brevo API key for the sender identity you want to use.
3. Copy `.env.example` to `.env`.
4. Set:
   - `BREVO_API_KEY=<your brevo api key>`
   - `BREVO_API_URL=https://api.brevo.com/v3/smtp/email`
   - `DEFAULT_FROM_EMAIL=SiteGuard Alerts <your verified sender>`
   - `SERVER_EMAIL=SiteGuard Alerts <your verified sender>`
   - `SUPPORT_EMAIL=<your support email>`
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
