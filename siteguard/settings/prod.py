# This file contains production-specific Django settings for SiteGuard.

import logging
from django.core.exceptions import ImproperlyConfigured
from urllib.parse import urlparse

from .base import *  # noqa: F401,F403
from .validation import validate_production_configuration

# Set DEBUG to False for security and performance in production.
DEBUG = False

# Secret key validation for production.
# Ensures that SECRET_KEY is explicitly set in the environment and not using a default insecure value.
if SECRET_KEY == "django-insecure-siteguard-dev-only-change-me":
    raise ImproperlyConfigured("SECRET_KEY must be set to a long random value for production.")

# Configure SQLite path for production, ensuring directory exists.
# This defaults to a `data` subdirectory within the base directory.
if SQLITE_PATH == DEFAULT_SQLITE_PATH:
    SQLITE_PATH = BASE_DIR / "data" / "siteguard.sqlite3"
    SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
    DATABASES["default"]["NAME"] = SQLITE_PATH

# Security settings for production environment.
SECURE_SSL_REDIRECT = config("SECURE_SSL_REDIRECT", default=True, cast=bool)

# TEMPORARY SESSION MANAGEMENT FOR RENDER DEPLOYMENT
#
# IMPORTANT: This is a TEMPORARY workaround until the project migrates to PostgreSQL
# or utilizes persistent disk storage on Render.
#
# Root Cause: Render's free-tier ephemeral SQLite resets invalidate database-backed sessions
# after redeploys/restarts.
#
# Solution: Switching to signed cookie sessions for production ONLY.
# This ensures session durability across ephemeral filesystem resets.
SESSION_ENGINE = "django.contrib.sessions.backends.signed_cookies"

# Cookie security hardening. These settings are crucial for production.
SESSION_COOKIE_AGE = config("SESSION_COOKIE_AGE", default=1209600, cast=int)  # 2 weeks
SESSION_COOKIE_SECURE = True  # Ensure cookies are only sent over HTTPS
CSRF_COOKIE_SECURE = True  # Ensure CSRF cookies are only sent over HTTPS
SESSION_COOKIE_HTTPONLY = True  # Prevent client-side JavaScript access to session cookies
CSRF_COOKIE_HTTPONLY = True  # Prevent client-side JavaScript access to CSRF cookies
SESSION_COOKIE_SAMESITE = "Lax"  # Protect against CSRF attacks
CSRF_COOKIE_SAMESITE = "Lax"  # Protect against CSRF attacks
SESSION_SAVE_EVERY_REQUEST = config("SESSION_SAVE_EVERY_REQUEST", default=True, cast=bool)
SESSION_EXPIRE_AT_BROWSER_CLOSE = config("SESSION_EXPIRE_AT_BROWSER_CLOSE", default=False, cast=bool)

# HTTP Strict Transport Security (HSTS) settings.
SECURE_HSTS_SECONDS = config("SECURE_HSTS_SECONDS", default=31536000, cast=int)  # 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = config(
    "SECURE_HSTS_INCLUDE_SUBDOMAINS",
    default=True,
    cast=bool,
)
SECURE_HSTS_PRELOAD = config("SECURE_HSTS_PRELOAD", default=True, cast=bool)

# Content Security Policy related headers.
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_OPENER_POLICY = "same-origin"
SECURE_CROSS_ORIGIN_RESOURCE_POLICY = "same-origin"

# Essential configuration checks for production.
if not ALLOWED_HOSTS:
    raise ImproperlyConfigured("ALLOWED_HOSTS must be configured for production.")

if not APP_BASE_URL:
    raise ImproperlyConfigured("APP_BASE_URL must be configured for production.")

parsed_app_base = urlparse(APP_BASE_URL)
if parsed_app_base.scheme != "https" or not parsed_app_base.netloc:
    raise ImproperlyConfigured("APP_BASE_URL must be a valid HTTPS URL in production.")

# Startup Diagnostics for Production
logger = logging.getLogger("siteguard.runtime")

logger.info("Production Configuration Diagnostics:")
logger.info(f"  SESSION_ENGINE: {SESSION_ENGINE}")
logger.info(f"  SESSION_COOKIE_SECURE: {SESSION_COOKIE_SECURE}")
logger.info(f"  SESSION_COOKIE_HTTPONLY: {SESSION_COOKIE_HTTPONLY}")
logger.info(f"  SESSION_COOKIE_SAMESITE: {SESSION_COOKIE_SAMESITE}")
logger.info(f"  CSRF_COOKIE_SECURE: {CSRF_COOKIE_SECURE}")
logger.info(f"  CSRF_COOKIE_HTTPONLY: {CSRF_COOKIE_HTTPONLY}")
logger.info(f"  CSRF_COOKIE_SAMESITE: {CSRF_COOKIE_SAMESITE}")
logger.info(f"  SECRET_KEY_PRESENT: {bool(SECRET_KEY and SECRET_KEY != 'django-insecure-siteguard-dev-only-change-me')}")
logger.info(f"  SESSION_COOKIE_AGE: {SESSION_COOKIE_AGE} seconds")
logger.info(f"  SESSION_EXPIRE_AT_BROWSER_CLOSE: {SESSION_EXPIRE_AT_BROWSER_CLOSE}")
# Render proxy settings are inherited from base.py
logger.info(f"  SECURE_PROXY_SSL_HEADER: {SECURE_PROXY_SSL_HEADER}")
logger.info(f"  USE_X_FORWARDED_HOST: {USE_X_FORWARDED_HOST}")

# Validate core production settings.
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

# Documentation for the temporary session change.
#
# Long-term Solution:
# The definitive solution involves migrating to a persistent database like PostgreSQL
# or configuring persistent disk storage on Render. This temporary measure will be
# reverted once a proper long-term solution is implemented.
