# Security Notes

## Secrets

- never commit `.env`
- keep `SECRET_KEY`, `CRON_SECRET`, and email credentials in Render environment variables only

## Production Safety

- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`
- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`

## Host Validation

- `ALLOWED_HOSTS` must include the Render hostname
- `CSRF_TRUSTED_ORIGINS` must include the full `https://` origin

## Cookie and HTTPS Controls

- secure cookies enabled in production
- HTTPOnly cookies enabled
- `SameSite=Lax` for session and CSRF cookies

## SQLite Risk

SQLite on Render free tier is not durable. It is acceptable for demos and low-risk environments, not for strict production durability requirements.

## Internal Trigger

- `/internal/run-monitoring/<token>/` is protected by `CRON_SECRET`
- do not expose the secret publicly

## Next Security Priorities

- PostgreSQL with backups
- dependency and secret scanning
- full 2FA implementation
