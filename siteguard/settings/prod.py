from django.core.exceptions import ImproperlyConfigured
from urllib.parse import urlparse

from .base import *  # noqa: F401,F403
from .validation import validate_production_configuration


DEBUG = False

if SQLITE_PATH == DEFAULT_SQLITE_PATH:
    SQLITE_PATH = BASE_DIR / "data" / "siteguard.sqlite3"
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATABASES["default"]["NAME"] = SQLITE_PATH

SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)
SESSION_ENGINE = _config_text(
    "SESSION_ENGINE",
    default="django.contrib.sessions.backends.signed_cookies",
)
SESSION_COOKIE_AGE = config("SESSION_COOKIE_AGE", default=1209600, cast=int)
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SESSION_SAVE_EVERY_REQUEST = config("SESSION_SAVE_EVERY_REQUEST", default=True, cast=bool)
SESSION_EXPIRE_AT_BROWSER_CLOSE = config("SESSION_EXPIRE_AT_BROWSER_CLOSE", default=False, cast=bool)
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", default=31536000, cast=int)
SECURE_HSTS_INCLUDE_SUBDOMAINS = config(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=True,
    cast=bool,
)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", default=True, cast=bool)
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"

if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be configured for production.")

if not APP_BASE_URL:
    raise ImproperlyConfigured("APP_BASE_URL must be configured for production.")

parsed_app_base = urlparse(APP_BASE_URL)
if parsed_app_base.scheme != "https" or not parsed_app_base.netloc:
    raise ImproperlyConfigured("APP_BASE_URL must be a valid HTTPS URL in production.")

validate_production_configuration(
    secret_key=SECRET_KEY,
    debug=DEBUG,
    allowed_hosts=ALLOWED_HOSTS,
    app_base_url=APP_BASE_URL,
    csrf_trusted_origins=CSRF_TRUSTED_ORIGINS,
    email_backend=EMAIL_BACKEND,
    email_host=EMAIL_HOST,
    email_use_tls=EMAIL_USE_TLS,
    email_use_ssl=EMAIL_USE_SSL,
    email_timeout=EMAIL_TIMEOUT,
    brevo_api_key=BREVO_API_KEY,
    default_from_email=DEFAULT_FROM_EMAIL,
    cloudinary_storage=CLOUDINARY_STORAGE,
    storages=STORAGES,
    cron_secret=CRON_SECRET,
)
