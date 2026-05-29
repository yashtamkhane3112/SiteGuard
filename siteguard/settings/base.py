import mimetypes
from pathlib import Path
from urllib.parse import urlparse
from email.utils import formataddr

from decouple import Csv, config

from .validation import build_sqlite_database_config, resolve_email_backend


BASE_DIR = Path(__file__).resolve().parent.parent.parent

mimetypes.add_type("application/manifest+json", ".webmanifest", True)


def _normalize_config_text(value, *, default=""):
    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text or default


def _config_text(name, *, default=""):
    raw_value = config(name, default=default)
    return _normalize_config_text(raw_value, default=default)

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
    "cloudinary",
    "cloudinary_storage",
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
                "django.template.context_processors.static",
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
SQLITE_TIMEOUT = config("SQLITE_TIMEOUT", default=20, cast=int)

DATABASES = {
    "default": build_sqlite_database_config(
        sqlite_path=SQLITE_PATH,
        sqlite_timeout=SQLITE_TIMEOUT,
    )
}

CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "siteguard-default",
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

CLOUDINARY_STORAGE = {
    "CLOUD_NAME": config("CLOUDINARY_CLOUD_NAME", default="").strip(),
    "API_KEY": config("CLOUDINARY_API_KEY", default="").strip(),
    "API_SECRET": config("CLOUDINARY_API_SECRET", default="").strip(),
}

STORAGES = {
    "default": {
        "BACKEND": "cloudinary_storage.storage.MediaCloudinaryStorage",
    },
    "staticfiles": {
        "BACKEND": "whitenoise.storage.CompressedManifestStaticFilesStorage",
    },
}
WHITENOISE_MAX_AGE = config("WHITENOISE_MAX_AGE", default=31536000, cast=int)
WHITENOISE_USE_FINDERS = DEBUG
WHITENOISE_MIMETYPES = {
    ".webmanifest": "application/manifest+json",
}

MEDIA_URL = "/media/"
FILE_UPLOAD_PERMISSIONS = 0o644
FILE_UPLOAD_DIRECTORY_PERMISSIONS = 0o755

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/login/"
LOGIN_REDIRECT_URL = "/dashboard/"
LOGOUT_REDIRECT_URL = "/login/"

SITE_NAME = _config_text("SITE_NAME", default="SiteGuard")
BREVO_API_KEY = _config_text("BREVO_API_KEY")
BREVO_API_URL = _config_text("BREVO_API_URL", default="https://api.brevo.com/v3/smtp/email")
EMAIL_HOST = _config_text("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT", default=587, cast=int)
EMAIL_USE_TLS = config("EMAIL_USE_TLS", default=True, cast=bool)
EMAIL_USE_SSL = config("EMAIL_USE_SSL", default=False, cast=bool)
EMAIL_TIMEOUT = config("EMAIL_TIMEOUT", default=15, cast=int)
EMAIL_HOST_USER = _config_text("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = _config_text("EMAIL_HOST_PASSWORD")
EMAIL_SENDER_NAME = _config_text("EMAIL_SENDER_NAME", default=f"{SITE_NAME} Alerts")
EMAIL_SUBJECT_PREFIX = _config_text("EMAIL_SUBJECT_PREFIX", default="[SiteGuard] ")
if EMAIL_SUBJECT_PREFIX and not EMAIL_SUBJECT_PREFIX.endswith(" "):
    EMAIL_SUBJECT_PREFIX = f"{EMAIL_SUBJECT_PREFIX} "
_default_sender_address = EMAIL_HOST_USER or "noreply@siteguard.local"
_default_from_email = formataddr((EMAIL_SENDER_NAME, _default_sender_address))
DEFAULT_FROM_EMAIL = _config_text("DEFAULT_FROM_EMAIL", default=_default_from_email)
SERVER_EMAIL = _config_text("SERVER_EMAIL", default=DEFAULT_FROM_EMAIL)
SUPPORT_EMAIL = _config_text("SUPPORT_EMAIL", default=EMAIL_HOST_USER or _default_sender_address)
configured_email_backend = _config_text("EMAIL_BACKEND")
EMAIL_BACKEND = resolve_email_backend(
    debug=DEBUG,
    configured_backend=configured_email_backend,
    brevo_api_key=BREVO_API_KEY,
)
PASSWORD_RESET_TIMEOUT = config("PASSWORD_RESET_TIMEOUT", default=86400, cast=int)

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
USE_X_FORWARDED_HOST = True

SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
REFERRER_POLICY = "same-origin"

APPEND_SLASH = True

BOOTSTRAP_ADMIN_ENABLED = config("BOOTSTRAP_ADMIN_ENABLED", default=DEBUG, cast=bool)
CRON_SECRET = _config_text("CRON_SECRET")
APP_BASE_URL = app_base_url
CANONICAL_BASE_URL = app_base_url
AI_FEATURES_ENABLED = config("AI_FEATURES_ENABLED", default=False, cast=bool)
AI_PROVIDER = _config_text("AI_PROVIDER", default="gemini").lower()
GEMINI_API_KEY = _config_text("GEMINI_API_KEY")
GEMINI_MODEL = _config_text("GEMINI_MODEL", default="gemini-1.5-flash")
OPENAI_API_KEY = _config_text("OPENAI_API_KEY")
OPENAI_MODEL = _config_text("OPENAI_MODEL", default="gpt-5-mini")
SESSION_ENGINE = _config_text("SESSION_ENGINE", default="django.contrib.sessions.backends.db")
SESSION_COOKIE_AGE = config("SESSION_COOKIE_AGE", default=1209600, cast=int)
SESSION_COOKIE_SECURE = config("SESSION_COOKIE_SECURE", default=False, cast=bool)
SESSION_COOKIE_HTTPONLY = config("SESSION_COOKIE_HTTPONLY", default=True, cast=bool)
SESSION_COOKIE_SAMESITE = _config_text("SESSION_COOKIE_SAMESITE", default="Lax")
SESSION_SAVE_EVERY_REQUEST = config("SESSION_SAVE_EVERY_REQUEST", default=True, cast=bool)
SESSION_EXPIRE_AT_BROWSER_CLOSE = config("SESSION_EXPIRE_AT_BROWSER_CLOSE", default=False, cast=bool)
CSRF_COOKIE_SECURE = config("CSRF_COOKIE_SECURE", default=False, cast=bool)
CSRF_COOKIE_HTTPONLY = config("CSRF_COOKIE_HTTPONLY", default=True, cast=bool)
CSRF_COOKIE_SAMESITE = _config_text("CSRF_COOKIE_SAMESITE", default="Lax")
AI_REQUEST_TIMEOUT = config("AI_REQUEST_TIMEOUT", default=20, cast=int)
AI_MAX_TOKENS = config("AI_MAX_TOKENS", default=900, cast=int)
AI_RETRY_ATTEMPTS = config("AI_RETRY_ATTEMPTS", default=2, cast=int)
AI_RETRY_BACKOFF_SECONDS = config("AI_RETRY_BACKOFF_SECONDS", default=0.5, cast=float)
AI_DEBUG_RAW_OUTPUT = config("AI_DEBUG_RAW_OUTPUT", default=False, cast=bool)
MONITOR_ALERT_ON_INITIAL_DOWN = config("MONITOR_ALERT_ON_INITIAL_DOWN", default=True, cast=bool)
MONITOR_LOG_RETENTION_DAYS = config("MONITOR_LOG_RETENTION_DAYS", default=90, cast=int)
MONITOR_LOG_RETENTION_BATCH_SIZE = config("MONITOR_LOG_RETENTION_BATCH_SIZE", default=500, cast=int)
MONITOR_LOG_RETENTION_MAX_BATCHES = config("MONITOR_LOG_RETENTION_MAX_BATCHES", default=20, cast=int)
MONITOR_DASHBOARD_LOG_WINDOW_DAYS = config("MONITOR_DASHBOARD_LOG_WINDOW_DAYS", default=30, cast=int)
MONITOR_LOG_LIST_WINDOW_DAYS = config("MONITOR_LOG_LIST_WINDOW_DAYS", default=90, cast=int)
MONITOR_RECENT_ACTIVITY_LIMIT = config("MONITOR_RECENT_ACTIVITY_LIMIT", default=20, cast=int)
MONITOR_SSRF_MAX_REDIRECTS = config("MONITOR_SSRF_MAX_REDIRECTS", default=3, cast=int)
AUTH_RATE_LIMIT_ATTEMPTS = config("AUTH_RATE_LIMIT_ATTEMPTS", default=5, cast=int)
AUTH_RATE_LIMIT_WINDOW_SECONDS = config("AUTH_RATE_LIMIT_WINDOW_SECONDS", default=900, cast=int)
SIGNUP_RATE_LIMIT_ATTEMPTS = config("SIGNUP_RATE_LIMIT_ATTEMPTS", default=5, cast=int)
SIGNUP_RATE_LIMIT_WINDOW_SECONDS = config("SIGNUP_RATE_LIMIT_WINDOW_SECONDS", default=3600, cast=int)
EMAIL_CONFIGURED = bool(
    DEFAULT_FROM_EMAIL and (
        (EMAIL_BACKEND == "brevo_api" and BREVO_API_KEY)
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
EMAIL_LOG_LEVEL = config("EMAIL_LOG_LEVEL", default="INFO" if DEBUG else "WARNING")
RUNTIME_LOG_LEVEL = config("RUNTIME_LOG_LEVEL", default="INFO" if DEBUG else "WARNING")

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
            "level": EMAIL_LOG_LEVEL,
            "propagate": False,
        },
        "siteguard.runtime": {
            "handlers": ["console"],
            "level": RUNTIME_LOG_LEVEL,
            "propagate": False,
        },
    },
}
