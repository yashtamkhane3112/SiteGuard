# Environment Setup

## Local Development

Local development uses SQLite unless you explicitly override it.

Required baseline:

- `SECRET_KEY`
- `DEBUG=True`
- optional `APP_BASE_URL`
- optional email settings

Recommended local bootstrap:

```powershell
Copy-Item .env.example .env
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
```

## Production Environment

Required:

- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `SECRET_KEY`
- `ALLOWED_HOSTS`
- `CSRF_TRUSTED_ORIGINS`
- `APP_BASE_URL`
- `CRON_SECRET`
- `DATABASE_URL`
- `BREVO_API_KEY`
- `DEFAULT_FROM_EMAIL`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

Recommended:

- `EMAIL_BACKEND=brevo_api`
- `SESSION_ENGINE=django.contrib.sessions.backends.db`
- `SESSION_SAVE_EVERY_REQUEST=True`
- `MONITOR_ALERT_ON_INITIAL_DOWN=True`
- `AI_FEATURES_ENABLED=False` unless Gemini features are intentionally enabled

## AI Configuration

Optional web-only AI configuration:

- `AI_FEATURES_ENABLED=True`
- `AI_PROVIDER=gemini`
- `GEMINI_API_KEY`
- `GEMINI_MODEL=gemini-2.5-flash`

Do not add AI credentials to the Render cron service unless monitoring ever needs them. Monitoring should stay independent from AI generation.

## Email Configuration

Production email should use Brevo API transport:

- `EMAIL_BACKEND=brevo_api`
- `BREVO_API_KEY`
- `BREVO_API_URL=https://api.brevo.com/v3/smtp/email`
- `DEFAULT_FROM_EMAIL`
- `SERVER_EMAIL`
- `SUPPORT_EMAIL`

Password reset emails, operational alert emails, and recovery emails all share the same final email transport layer.
