#!/usr/bin/env bash
set -euo pipefail

export DJANGO_SETTINGS_MODULE="${DJANGO_SETTINGS_MODULE:-siteguard.settings.prod}"

echo "SiteGuard startup: using settings module ${DJANGO_SETTINGS_MODULE}"
echo "Running database migrations..."
python manage.py migrate --settings=siteguard.settings.prod --noinput

echo "Verifying auth tables..."
python - <<'PY'
import os
import sys

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "siteguard.settings.prod")

import django
django.setup()

from django.contrib.auth.models import User
from django.db import connection

table_names = set(connection.introspection.table_names())
required_table = User._meta.db_table

if required_table not in table_names:
    print(f"Missing required auth table: {required_table}", file=sys.stderr)
    sys.exit(1)

print(f"Verified required auth table: {required_table}")
PY

echo "Collecting static files..."
python manage.py collectstatic --noinput --settings=siteguard.settings.prod

echo "Starting Gunicorn..."
exec gunicorn siteguard.wsgi:application
