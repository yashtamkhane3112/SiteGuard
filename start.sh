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

echo "Checking auth table and session backend..."
python manage.py shell --settings="${DJANGO_SETTINGS_MODULE}" -c "
from django.conf import settings
from django.db import connection
table_names = set(connection.introspection.table_names())
assert 'auth_user' in table_names, 'auth_user table missing'
session_engine = getattr(settings, 'SESSION_ENGINE', '')
if session_engine == 'django.contrib.sessions.backends.db':
    assert 'django_session' in table_names, 'django_session table missing'
    print('Session backend requires django_session and the table is present.')
else:
    print(f'Session backend {session_engine} does not require django_session persistence.')
"

echo "Collecting static..."
python manage.py collectstatic --noinput --settings="${DJANGO_SETTINGS_MODULE}"

echo "Starting gunicorn..."
exec gunicorn siteguard.wsgi:application --bind 0.0.0.0:${PORT:-10000}
