#!/usr/bin/env bash
set -euo pipefail

trap 'echo "Startup failed at line ${LINENO}" >&2' ERR

export DJANGO_SETTINGS_MODULE="siteguard.settings.prod"

echo "STARTUP SCRIPT RUNNING"
echo "Working directory: $(pwd)"
echo "Python: $(python --version)"
echo "Using settings: ${DJANGO_SETTINGS_MODULE}"

command -v python >/dev/null 2>&1
command -v gunicorn >/dev/null 2>&1

echo "Running migrations..."
python manage.py migrate --settings="${DJANGO_SETTINGS_MODULE}" --noinput

bootstrap_admin_flag="$(printf '%s' "${DJANGO_BOOTSTRAP_ADMIN:-False}" | tr '[:upper:]' '[:lower:]')"
if [[ "${bootstrap_admin_flag}" == "true" ]]; then
  echo "Admin bootstrap executed: running bootstrap_admin..."
  if python manage.py bootstrap_admin --settings="${DJANGO_SETTINGS_MODULE}"; then
    echo "Admin bootstrap success."
  else
    echo "Admin bootstrap failure." >&2
    exit 1
  fi
else
  echo "Admin bootstrap skipped."
fi

echo "Checking auth table..."
python manage.py shell --settings="${DJANGO_SETTINGS_MODULE}" -c "
from django.db import connection
cursor = connection.cursor()
cursor.execute(\"SELECT name FROM sqlite_master WHERE type='table' AND name='auth_user';\")
result = cursor.fetchone()
assert result is not None, 'auth_user table missing'
"

echo "Collecting static..."
python manage.py collectstatic --noinput --settings="${DJANGO_SETTINGS_MODULE}"

echo "Starting gunicorn..."
exec gunicorn siteguard.wsgi:application --bind 0.0.0.0:${PORT:-10000}
