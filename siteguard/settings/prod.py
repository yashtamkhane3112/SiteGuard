from django.core.exceptions import ImproperlyConfigured
from urllib.parse import urlparse

from .base import *  # noqa: F401,F403


DEBUG = False

if SECRET_KEY == "django-insecure-siteguard-dev-only-change-me":
    raise ImproperlyConfigured("SECRET_KEY must be set in production.")

if SQLITE_PATH == DEFAULT_SQLITE_PATH:
    SQLITE_PATH = BASE_DIR / "data" / "siteguard.sqlite3"
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATABASES["default"]["NAME"] = SQLITE_PATH

SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", default=31536000, cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=True,
    cast=bool,
)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", default=True, cast=bool)
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"

if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be configured for production.")

if not APP_BASE_URL:
    raise ImproperlyConfigured("APP_BASE_URL must be configured for production.")

parsed_app_base = urlparse(APP_BASE_URL)
if parsed_app_base.scheme != "https" or not parsed_app_base.netloc:
    raise ImproperlyConfigured("APP_BASE_URL must be a valid HTTPS URL in production.")

if EMAIL_BACKEND == "django.core.mail.backends.smtp.EmailBackend" and EMAIL_USE_TLS and EMAIL_USE_SSL:
    raise ImproperlyConfigured("EMAIL_USE_TLS and EMAIL_USE_SSL cannot both be enabled.")
