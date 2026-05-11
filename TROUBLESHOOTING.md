# Troubleshooting

## `auth_user` Missing Table

Symptoms:

- homepage works
- signup/login GET works
- signup/login POST fails
- `django.db.utils.OperationalError: no such table: auth_user`

Fix:

- ensure Render start command is `bash ./start.sh`
- redeploy
- confirm logs show `Checking auth table...`

## Static File Issues

- confirm `Collecting static...` appears in startup logs
- confirm WhiteNoise is enabled
- confirm `/static/` files do not return 404

## CSRF Issues

- `CSRF_TRUSTED_ORIGINS` must include the full Render origin
- `ALLOWED_HOSTS` must include the hostname
- use the canonical HTTPS URL

## Render Startup Issues

- confirm `start.sh` exists at repo root
- confirm dashboard start command is exactly `bash ./start.sh`
- confirm the file is executable in git

## Migration Failures

- inspect deploy logs for the migrate step
- verify production settings are loaded
- verify `SECRET_KEY` and `ALLOWED_HOSTS` are set

## SQLite Notes

- data can be lost on restart or redeploy
- startup migrations are required every boot

## Deployment Debugging

- open `/health/`
- inspect deploy logs
- verify `render.yaml` and `Procfile`
- verify committed migrations under `monitor/migrations/`
