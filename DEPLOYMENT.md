# Deployment

## Production Topology

SiteGuard runs on Render with:

- one Django web service
- one Render cron service that triggers the protected monitoring endpoint
- Neon PostgreSQL for persistent production data
- database-backed Django sessions
- database-backed Django cache for cross-worker rate limiting
- WhiteNoise for static files
- Cloudinary for media and raw analyzer uploads
- Brevo API delivery for transactional email

## Render Services

Web service:

- build command: `pip install -r requirements.txt`
- start command: `bash ./start.sh`
- settings module: `siteguard.settings.prod`

Cron service:

- schedule: `*/5 * * * *`
- start command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

The cron job must not run direct ORM writes against a separate local SQLite file. It should always call the web runtime so monitoring and persistence happen inside the same application environment.

## Startup Sequence

[`start.sh`](start.sh) performs:

1. load production settings
2. run migrations
3. ensure the `siteguard_cache` table exists for Django DatabaseCache
4. optionally run admin bootstrap when explicitly enabled
5. verify DB readiness and required tables
6. collect static files
7. start Gunicorn

## Production Rules

- Use Neon `DATABASE_URL` with SSL enabled.
- Keep `SESSION_ENGINE=django.contrib.sessions.backends.db`.
- Keep production `CACHES["default"]` on Django DatabaseCache. `start.sh` runs `createcachetable` so auth and signup rate limits are shared across Gunicorn workers.
- Keep `DJANGO_BOOTSTRAP_ADMIN=False` after one-time superuser setup.
- Do not replace `bash ./start.sh` with a raw Gunicorn command.
- Keep `DEBUG=False`.

## Validation

```powershell
.\.venv\Scripts\python.exe manage.py check --deploy --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py collectstatic --dry-run --noinput --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py showmigrations monitor --settings=siteguard.settings.prod
```
