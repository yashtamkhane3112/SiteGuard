# Environment Variables

## Required in Production

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `RESEND_API_KEY`
- `DEFAULT_FROM_EMAIL`

## Optional

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
- SiteGuard sends email through Resend only, using `EMAIL_BACKEND = "anymail.backends.resend.EmailBackend"`.
- Password reset emails use the active local request host during `DEBUG=True` development flows, so local forgot-password links stay on `127.0.0.1`, `localhost`, or the host you are actively using.
- Production password reset and operational email links use `APP_BASE_URL` / `CANONICAL_BASE_URL`, which must stay HTTPS on Render.

## Local Resend Setup

For real local mail delivery with Resend:

1. Create a Resend API key with sending access.
2. Verify the sender domain or use an approved Resend test sender while validating the integration.
3. Copy `.env.example` to `.env`.
4. Set:
   - `RESEND_API_KEY=<your resend api key>`
   - `DEFAULT_FROM_EMAIL=SiteGuard Alerts <approved@your-domain>`
   - `SERVER_EMAIL=SiteGuard Alerts <approved@your-domain>`
   - `SUPPORT_EMAIL=support@your-domain`
5. Keep `DJANGO_SETTINGS_MODULE=siteguard.settings.dev` for local work unless you are intentionally testing production settings.
6. For local forgot-password testing, open the site on the exact host you want reflected in the email link, such as `http://127.0.0.1:8000` or `http://localhost:8000`.

Useful verification commands:

```bash
python manage.py test_email your@email.com
python manage.py test_email your@email.com --kind operational --site https://example.com
python manage.py test_email your@email.com --kind password_reset
```

## Reference

Use [.env.example](/E:/Testing%20django%202/Testing/siteguard/.env.example:1) as the starting template.
