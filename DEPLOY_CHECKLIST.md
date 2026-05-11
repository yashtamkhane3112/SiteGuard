# Deploy Checklist

## Render Settings

- runtime: `Python`
- `DJANGO_SETTINGS_MODULE=siteguard.settings.prod`
- `DEBUG=False`
- `BOOTSTRAP_ADMIN_ENABLED=False`

## Commands

- build command: `pip install -r requirements.txt`
- start command: `bash ./start.sh`
- cron command: `curl -fsS "$APP_BASE_URL/internal/run-monitoring/$CRON_SECRET/"`

## Migration Verification

- logs show `STARTUP SCRIPT RUNNING`
- logs show `Running migrations...`
- logs show `Checking auth table...`
- logs show `('auth_user',)`

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

## Rollback Checklist

- return to previous stable commit
- redeploy Render
- confirm start command still uses `bash ./start.sh`
- re-run health and auth checks
