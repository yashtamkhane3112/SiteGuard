# Deploy Checklist

## Render Settings

- runtime: `Python`
- Python version: `3.12.3`
- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`
- `DATABASE_URL=<neon postgres url>`
- `SESSION_ENGINE=django.contrib.sessions.backends.db`

## Commands

- build command: `pip install -r requirements.txt`
- start command: `bash ./start.sh`
- cron command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

## Migration Verification

- logs show `STARTUP SCRIPT RUNNING`
- logs show `Running migrations...`
- logs show `Database startup diagnostics:`
- logs show `connection_health=healthy`
- logs show `Checking database readiness...`

## Auth Verification

- homepage GET works
- signup GET and POST work
- login GET and POST work

## Static Verification

- logs show `Collecting static...`
- homepage CSS loads
- dashboard CSS loads
- static assets do not 404

## Production Verification Flow

1. open `/health/`
2. confirm `status: ok`
3. complete signup/login flow
4. add a website
5. trigger cron endpoint
6. confirm logs and monitoring data update
7. confirm uploads still store through Cloudinary raw storage
8. confirm authenticated sessions survive refresh/restart behavior

## Local Environment Alignment

- local Python must be `3.12.3`
- recreate `.venv` if it was created on Python `3.14`
- verify with `python --version` before testing admin pages

## Rollback Checklist

- return to previous stable commit
- redeploy Render
- confirm start command still uses `bash ./start.sh`
- re-run health and auth checks
