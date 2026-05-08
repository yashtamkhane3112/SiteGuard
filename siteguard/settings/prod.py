from django.core.exceptions import ImproperlyConfigured
from pathlib import Path

from .base import *  # noqa: F401,F403


DEBUG = False

if SECRET_KEY == "django-insecure-siteguard-dev-only-change-me":
    raise ImproperlyConfigured("SECRET_KEY must be set in production.")

default_prod_sqlite = BASE_DIR / "data" / "siteguard.sqlite3"
if render_hostname:
    default_prod_sqlite = Path("/tmp/siteguard.sqlite3")
if SQLITE_PATH == DEFAULT_SQLITE_PATH:
    SQLITE_PATH = default_prod_sqlite
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATABASES["default"]["NAME"] = SQLITE_PATH

SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", default=3600, cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=False,
    cast=bool,
)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", default=False, cast=bool)
SECURE_REFERRER_POLICY = "same-origin"

if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be configured for production.")
