import os
from pathlib import Path
from urllib.parse import urlparse
from email.utils import formataddr

from decouple import Csv, config


BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = config(
    "SECRET_KEY",
    default="django-insecure-siteguard-dev-only-change-me",
)

DEBUG = config("DEBUG", default=True, cast=bool)

ALLOWED_HOSTS = config(
    "ALLOWED_HOSTS",
    default="127.0.0.1,localhost,testserver",
    cast=Csv(),
)

render_hostname = config("RENDER_EXTERNAL_HOSTNAME", default="").strip()
if render_hostname and render_hostname not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(render_hostname)

csrf_trusted_origins = config(
    "CSRF_TRUSTED_ORIGINS",
    default="",
    cast=Csv(),
)
if render_hostname:
    render_origin = f"https://{render_hostname}"
    if render_origin not in csrf_trusted_origins:
        csrf_trusted_origins.append(render_origin)
app_base_url = config("APP_BASE_URL", default="").rstrip("/")
if not app_base_url and render_hostname:
    app_base_url = f"https://{render_hostname}"
if app_base_url:
    parsed_app_base = urlparse(app_base_url)
    app_origin = f"{parsed_app_base.scheme}://{parsed_app_base.netloc}" if parsed_app_base.scheme and parsed_app_base.netloc else ""
    if app_origin and app_origin not in csrf_trusted_origins:
        csrf_trusted_origins.append(app_origin)
CSRF_TRUSTED_ORIGINS = csrf_trusted_origins

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "monitor",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "siteguard.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "monitor.context_processors.global_ui_context",
            ],
        },
    },
]

WSGI_APPLICATION = "siteguard.wsgi.application"
ASGI_APPLICATION = "siteguard.asgi.application"

DEFAULT_SQLITE_PATH = BASE_DIR / "db.sqlite3"
SQLITE_PATH = Path(config("SQLITE_PATH", default=str(DEFAULT_SQLITE_PATH)))
SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": SQLITE_PATH,
        "OPTIONS": {
            "timeout": config("SQLITE_TIMEOUT", default=20, cast=int),
        },
    }
}

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = config("TIME_ZONE", default="UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
STORAGES = {
    "default": {
        "BACKEND": "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}
WHITENOISE_MAX_AGE = config("WHITENOISE_MAX_AGE", default=31536000, cast=int)
WHITENOISE_USE_FINDERS = DEBUG

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/login/"

SITE_NAME = config("SITE_NAME", default="SiteGuard").strip() or "SiteGuard"
BREVO_API_KEY = config("BREVO_API_KEY", default="").strip()
BREVO_API_URL = config("BREVO_API_URL", default="https://api.brevo.com/v3/smtp/email").strip()
EMAIL_HOST = config("EMAIL_HOST", default="smtp-relay.brevo.com").strip()
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_USE_SSL = config("EMAIL_USE_SSL", default=False, cast=bool)
EMAIL_TIMEOUT = config("EMAIL_TIMEOUT", default=15, cast=int)
BREVO_SMTP_LOGIN = config("BREVO_SMTP_LOGIN", default="").strip()
BREVO_SMTP_PASSWORD = config("BREVO_SMTP_PASSWORD", default="").strip()
EMAIL_HOST_USER = config("EMAIL_HOST_USER", default="").strip() or BREVO_SMTP_LOGIN
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD", default="").strip() or BREVO_SMTP_PASSWORD
EMAIL_SENDER_NAME = config("EMAIL_SENDER_NAME", default=f"{SITE_NAME} Alerts").strip() or f"{SITE_NAME} Alerts"
EMAIL_SUBJECT_PREFIX = config("EMAIL_SUBJECT_PREFIX", default="[SiteGuard] ").strip()
if EMAIL_SUBJECT_PREFIX and not EMAIL_SUBJECT_PREFIX.endswith(" "):
    EMAIL_SUBJECT_PREFIX = f"{EMAIL_SUBJECT_PREFIX} "
_default_sender_address = EMAIL_HOST_USER or "noreply@siteguard.local"
_default_from_email = formataddr((EMAIL_SENDER_NAME, _default_sender_address))
DEFAULT_FROM_EMAIL = config("DEFAULT_FROM_EMAIL", default=_default_from_email).strip()
SERVER_EMAIL = config("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)
SUPPORT_EMAIL = config("SUPPORT_EMAIL", default=EMAIL_HOST_USER or _default_sender_address).strip()
configured_email_backend = config("EMAIL_BACKEND", default="").strip()
if configured_email_backend:
    EMAIL_BACKEND = configured_email_backend
elif DEBUG and not BREVO_API_KEY:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
else:
    EMAIL_BACKEND = "brevo_api"
PASSWORD_RESET_TIMEOUT = config("PASSWORD_RESET_TIMEOUT", default=86400, cast=int)

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
REFERRER_POLICY = "same-origin"

APPEND_SLASH = True

BOOTSTRAP_ADMIN_ENABLED = config("BOOTSTRAP_ADMIN_ENABLED", default=DEBUG, cast=bool)
CRON_SECRET = config("CRON_SECRET", default="")
APP_BASE_URL = app_base_url
CANONICAL_BASE_URL = app_base_url
EMAIL_CONFIGURED = bool(
    DEFAULT_FROM_EMAIL and (
        BREVO_API_KEY
        or (
            EMAIL_BACKEND == "django.core.mail.backends.smtp.EmailBackend"
            and EMAIL_HOST
            and EMAIL_HOST_USER
            and EMAIL_HOST_PASSWORD
        )
        or EMAIL_BACKEND in {
            "django.core.mail.backends.console.EmailBackend",
            "django.core.mail.backends.locmem.EmailBackend",
            "django.core.mail.backends.filebased.EmailBackend",
            "django.core.mail.backends.dummy.EmailBackend",
        }
    )
)

LOG_LEVEL = config("LOG_LEVEL", default="INFO")
DJANGO_LOG_LEVEL = config("DJANGO_LOG_LEVEL", default="INFO")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s",
        },
        "verbose": {
            "format": "%(asctime)s %(levelname)s %(name)s %(message)s %(email_context)s",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "standard",
        },
        "email_console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "loggers": {
        "": {
            "handlers": ["console"],
            "level": LOG_LEVEL,
        },
        "django": {
            "handlers": ["console"],
            "level": DJANGO_LOG_LEVEL,
            "propagate": False,
        },
        "siteguard.email": {
            "handlers": ["email_console"],
            "level": LOG_LEVEL,
            "propagate": False,
        },
    },
}
