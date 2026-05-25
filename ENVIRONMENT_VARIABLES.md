# Environment Variables

## Required in Production

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `DATABASE_URL`
- `EMAIL_BACKEND=brevo_api`
- `BREVO_API_KEY`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`
- `DEFAULT_FROM_EMAIL`

## Optional

- `EMAIL_BACKEND`
- `EMAIL_TIMEOUT`
- `BREVO_API_URL`
- `EMAIL_HOST`
- `EMAIL_PORT`
- `EMAIL_USE_TLS`
- `EMAIL_USE_SSL`
- `EMAIL_HOST_USER`
- `EMAIL_HOST_PASSWORD`
- `SERVER_EMAIL`
- `SUPPORT_EMAIL`
- `EMAIL_SENDER_NAME`
- `EMAIL_LOG_LEVEL`
- `RUNTIME_LOG_LEVEL`
- `SQLITE_PATH`
- `SQLITE_TIMEOUT`
- `SITE_NAME`
- `EMAIL_SUBJECT_PREFIX`
- `LOG_LEVEL`
- `DJANGO_LOG_LEVEL`
- `WHITENOISE_MAX_AGE`
- `AI_FEATURES_ENABLED`
- `AI_PROVIDER`
- `GEMINI_API_KEY`
- `GEMINI_MODEL`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `SESSION_ENGINE`
- `SESSION_COOKIE_AGE`
- `SESSION_COOKIE_SECURE`
- `SESSION_COOKIE_SAMESITE`
- `SESSION_SAVE_EVERY_REQUEST`
- `SESSION_EXPIRE_AT_BROWSER_CLOSE`
- `CSRF_COOKIE_SECURE`
- `CSRF_COOKIE_SAMESITE`
- `AI_REQUEST_TIMEOUT`
- `AI_MAX_TOKENS`
- `AI_RETRY_ATTEMPTS`
- `AI_RETRY_BACKOFF_SECONDS`

Default production SQLite path is `data/siteguard.sqlite3` unless `SQLITE_PATH` is explicitly set. Production should use `DATABASE_URL` for Neon PostgreSQL.

Notes:

- `APP_BASE_URL` must be a valid HTTPS URL in production because password reset emails and operational links are generated from it.
- Local development defaults to `django.core.mail.backends.console.EmailBackend` unless you explicitly force another backend.
- Gmail SMTP is intended for local development only.
- Production should use the Brevo HTTPS API backend and `BREVO_API_KEY`.
- Production should use the Neon PostgreSQL `DATABASE_URL` with SSL enabled.
- Password reset emails use the active local request host during `DEBUG=True` development flows, so local forgot-password links stay on `127.0.0.1`, `localhost`, or the host you are actively using.
- Production password reset and operational email links use `APP_BASE_URL` / `CANONICAL_BASE_URL`, which must stay HTTPS on Render.
- Render terminates HTTPS at the proxy. Keep `SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https")` and `USE_X_FORWARDED_HOST=True` so Django treats forwarded requests as secure.
- Production now defaults to `SESSION_ENGINE=django.contrib.sessions.backends.db`.
- Keep `python manage.py migrate` in the Render startup flow so the `django_session` table exists before serving traffic.
- Startup diagnostics now log the database engine, host, database name, SSL mode, and connection health.
- `SESSION_COOKIE_AGE` defaults to 14 days and `SESSION_SAVE_EVERY_REQUEST=True` refreshes active sessions without weakening HTTPS-only cookie behavior in production.
- AI operational intelligence is disabled by default. Set `AI_FEATURES_ENABLED=True`, `AI_PROVIDER=gemini`, and `GEMINI_API_KEY` on the web service to enable on-demand report, error, and incident analysis.
- Production should set `GEMINI_MODEL=gemini-2.5-flash`.
- Gemini calls use the official `google-generativeai` Python SDK with `configure(api_key=...)` and `GenerativeModel(...)`.
- Gemini transient quota/service failures such as `429`, `500`, `502`, `503`, and `504` are retried with `AI_RETRY_ATTEMPTS` and `AI_RETRY_BACKOFF_SECONDS`.
- Gemini auth failures, unavailable models, malformed responses, and timeouts are handled gracefully and cached as failed AI generation without breaking monitoring or report pages.
- Startup logs now emit AI diagnostics with `AI_FEATURES_ENABLED`, `AI_PROVIDER`, resolved `GEMINI_MODEL`, and whether the Gemini API key is present.
- Run `python manage.py test_ai_provider` to verify the active provider configuration and execute a minimal AI self-test.
- OpenAI remains supported with `AI_PROVIDER=openai`, `OPENAI_API_KEY`, and `OPENAI_MODEL`.
- AI generation is read-only and cached. The cron job does not need AI provider credentials because monitor execution must not call AI providers.

## Local SMTP Setup

For real local mail delivery with Gmail SMTP:

1. Create an app password for the Gmail account you want to use.
3. Copy `.env.example` to `.env`.
4. Set:
   - `EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend`
   - `EMAIL_HOST=smtp.gmail.com`
   - `EMAIL_PORT=587`
   - `EMAIL_USE_TLS=True`
   - `EMAIL_USE_SSL=False`
   - `EMAIL_HOST_USER=<your gmail address>`
   - `EMAIL_HOST_PASSWORD=<your app password>`
   - `DEFAULT_FROM_EMAIL=SiteGuard Alerts <your gmail address>`
   - `SERVER_EMAIL=SiteGuard Alerts <your gmail address>`
   - `SUPPORT_EMAIL=<your gmail address>`
5. Do not use the Gmail SMTP transport in production.
6. For local forgot-password testing, open the site on the exact host you want reflected in the email link, such as `http://127.0.0.1:8000` or `http://localhost:8000`.

Useful verification commands:

```bash
python manage.py test_email your@email.com
python manage.py test_email your@email.com --kind operational --site https://example.com
python manage.py test_email your@email.com --kind password_reset
```

## Reference

Use [.env.example](/E:/Testing%20django%202/Testing/siteguard/.env.example:1) as the starting template.
