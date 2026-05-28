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

echo "Ensuring database cache table exists..."
python manage.py createcachetable --settings="${DJANGO_SETTINGS_MODULE}" --database default

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

echo "Checking database readiness..."
python manage.py shell --settings="${DJANGO_SETTINGS_MODULE}" -c "
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.sessions.models import Session
from django.db import connection
with connection.cursor() as cursor:
    cursor.execute(\"SELECT 1\")
    result = cursor.fetchone()
    assert result is not None and result[0] == 1, 'database connection probe failed'
table_names = set(connection.introspection.table_names())
assert User._meta.db_table in table_names, 'auth_user table missing'
if getattr(settings, 'SESSION_ENGINE', '') == 'django.contrib.sessions.backends.db':
    assert Session._meta.db_table in table_names, 'django_session table missing'
"

echo "Collecting static..."
python manage.py collectstatic --noinput --settings="${DJANGO_SETTINGS_MODULE}"

GUNICORN_WORKERS="${WEB_CONCURRENCY:-2}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-90}"
GUNICORN_GRACEFUL_TIMEOUT="${GUNICORN_GRACEFUL_TIMEOUT:-30}"
GUNICORN_MAX_REQUESTS="${GUNICORN_MAX_REQUESTS:-1000}"
GUNICORN_MAX_REQUESTS_JITTER="${GUNICORN_MAX_REQUESTS_JITTER:-100}"
GUNICORN_KEEPALIVE="${GUNICORN_KEEPALIVE:-5}"

echo "Starting gunicorn..."
echo "Gunicorn config: workers=${GUNICORN_WORKERS} timeout=${GUNICORN_TIMEOUT} graceful_timeout=${GUNICORN_GRACEFUL_TIMEOUT} max_requests=${GUNICORN_MAX_REQUESTS} jitter=${GUNICORN_MAX_REQUESTS_JITTER} keepalive=${GUNICORN_KEEPALIVE}"
exec gunicorn siteguard.wsgi:application \
  --bind 0.0.0.0:${PORT:-10000} \
  --workers "${GUNICORN_WORKERS}" \
  --timeout "${GUNICORN_TIMEOUT}" \
  --graceful-timeout "${GUNICORN_GRACEFUL_TIMEOUT}" \
  --max-requests "${GUNICORN_MAX_REQUESTS}" \
  --max-requests-jitter "${GUNICORN_MAX_REQUESTS_JITTER}" \
  --keep-alive "${GUNICORN_KEEPALIVE}"
