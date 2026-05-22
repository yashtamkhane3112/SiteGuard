from django.apps import AppConfig
from django.conf import settings
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError
import logging
import warnings


logger = logging.getLogger("siteguard.runtime")


_startup_diagnostics_logged = False


def _normalize_runtime_text(value):
    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text


def log_ai_startup_diagnostics():
    provider_name = _normalize_runtime_text(getattr(settings, "AI_PROVIDER", "gemini") or "gemini").lower() or "gemini"
    configured_model = _normalize_runtime_text(getattr(settings, "GEMINI_MODEL", ""))
    resolved_model = configured_model
    if configured_model and not configured_model.startswith("models/"):
        resolved_model = f"models/{configured_model}"

    logger.info(
        "AI startup diagnostics: AI_FEATURES_ENABLED=%s AI_PROVIDER=%s GEMINI_MODEL=%s GEMINI_API_KEY_PRESENT=%s",
        bool(getattr(settings, "AI_FEATURES_ENABLED", False)),
        provider_name,
        resolved_model or "(not set)",
        bool(getattr(settings, "GEMINI_API_KEY", "")),
        extra={
            "ai_features_enabled": bool(getattr(settings, "AI_FEATURES_ENABLED", False)),
            "ai_provider": provider_name,
            "gemini_model": resolved_model or "",
            "gemini_api_key_present": bool(getattr(settings, "GEMINI_API_KEY", "")),
        },
    )


def log_session_startup_diagnostics():
    session_engine = getattr(settings, "SESSION_ENGINE", "")
    default_db_name = ""
    session_table_exists = None
    session_table_name = "django_session"
    try:
        default_db_name = str(settings.DATABASES.get("default", {}).get("NAME", ""))
    except Exception:
        default_db_name = ""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            session_table_exists = session_table_name in connection.introspection.table_names()
    except (OperationalError, ProgrammingError):
        session_table_exists = None

    logger.info(
        "Session startup diagnostics: engine=%s cookie_age=%s secure=%s samesite=%s save_every_request=%s expire_at_browser_close=%s proxy_ssl_header=%s use_x_forwarded_host=%s csrf_secure=%s csrf_samesite=%s backend_health=%s",
        session_engine,
        int(getattr(settings, "SESSION_COOKIE_AGE", 0) or 0),
        bool(getattr(settings, "SESSION_COOKIE_SECURE", False)),
        getattr(settings, "SESSION_COOKIE_SAMESITE", ""),
        bool(getattr(settings, "SESSION_SAVE_EVERY_REQUEST", False)),
        bool(getattr(settings, "SESSION_EXPIRE_AT_BROWSER_CLOSE", False)),
        getattr(settings, "SECURE_PROXY_SSL_HEADER", None),
        bool(getattr(settings, "USE_X_FORWARDED_HOST", False)),
        bool(getattr(settings, "CSRF_COOKIE_SECURE", False)),
        getattr(settings, "CSRF_COOKIE_SAMESITE", ""),
        "healthy" if session_table_exists is True or session_engine != "django.contrib.sessions.backends.db" else "table_unavailable" if session_table_exists is False else "unknown",
        extra={
            "session_engine": session_engine,
            "session_cookie_age": int(getattr(settings, "SESSION_COOKIE_AGE", 0) or 0),
            "session_cookie_secure": bool(getattr(settings, "SESSION_COOKIE_SECURE", False)),
            "session_cookie_samesite": getattr(settings, "SESSION_COOKIE_SAMESITE", ""),
            "session_save_every_request": bool(getattr(settings, "SESSION_SAVE_EVERY_REQUEST", False)),
            "session_expire_at_browser_close": bool(getattr(settings, "SESSION_EXPIRE_AT_BROWSER_CLOSE", False)),
            "secure_proxy_ssl_header": getattr(settings, "SECURE_PROXY_SSL_HEADER", None),
            "use_x_forwarded_host": bool(getattr(settings, "USE_X_FORWARDED_HOST", False)),
            "csrf_cookie_secure": bool(getattr(settings, "CSRF_COOKIE_SECURE", False)),
            "csrf_cookie_samesite": getattr(settings, "CSRF_COOKIE_SAMESITE", ""),
            "session_db_name": default_db_name,
            "session_table_name": session_table_name,
            "session_table_exists": session_table_exists,
        },
    )

    normalized_db_name = default_db_name.replace("\\", "/").lower()
    if (
        not getattr(settings, "DEBUG", False)
        and session_engine == "django.contrib.sessions.backends.db"
        and default_db_name
        and "siteguard.sqlite3" in normalized_db_name
        and "/data/" not in normalized_db_name
    ):
        logger.warning(
            "Production session engine is using the database backend on a non-persistent local SQLite path. On Render this can invalidate sessions after deploys or instance restarts.",
            extra={
                "runtime_context": {
                    "session_engine": session_engine,
                    "database_name": default_db_name,
                }
            },
        )

    if session_engine == "django.contrib.sessions.backends.db" and session_table_exists is False:
        logger.warning(
            "Production session backend is configured for database sessions, but the django_session table is unavailable.",
            extra={
                "runtime_context": {
                    "session_engine": session_engine,
                    "session_table_name": session_table_name,
                    "database_name": default_db_name,
                }
            },
        )


def log_analyzer_storage_startup_diagnostics():
    from .models import UploadedLog

    storage = UploadedLog._meta.get_field("file").storage
    if hasattr(storage, "get_debug_metadata"):
        metadata = storage.get_debug_metadata()
    else:
        metadata = {
            "storage_class": f"{storage.__class__.__module__}.{storage.__class__.__name__}",
            "delegate_class": "",
            "resource_type": getattr(storage, "RESOURCE_TYPE", ""),
            "active_media_backend": ((getattr(settings, "STORAGES", {}) or {}).get("default", {}) or {}).get("BACKEND", ""),
            "available": True,
            "error": "",
        }

    logger.info(
        "Analyzer storage startup diagnostics: field_storage=%s delegate=%s resource_type=%s active_media_backend=%s available=%s",
        metadata.get("storage_class", ""),
        metadata.get("delegate_class", ""),
        metadata.get("resource_type", ""),
        metadata.get("active_media_backend", ""),
        bool(metadata.get("available", False)),
        extra={"analyzer_storage": metadata},
    )

    if not metadata.get("available", False):
        logger.warning(
            "Analyzer upload storage is unavailable.",
            extra={"analyzer_storage": metadata},
        )


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        global _startup_diagnostics_logged
        if not _startup_diagnostics_logged:
            log_ai_startup_diagnostics()
            log_session_startup_diagnostics()
            log_analyzer_storage_startup_diagnostics()
            _startup_diagnostics_logged = True

        if getattr(settings, "DEBUG", False):
            return

        storage_backend = settings.STORAGES.get("default", {}).get("BACKEND", "")
        if storage_backend == "django.core.files.storage.FileSystemStorage":
            logger.warning(
                "Production media storage is using the local filesystem. On Render free instances, uploaded media is ephemeral and can disappear after deploys or restarts.",
                extra={
                    "runtime_context": {
                        "storage_backend": storage_backend,
                        "media_root": str(getattr(settings, "MEDIA_ROOT", "")),
                        "media_url": getattr(settings, "MEDIA_URL", ""),
                        "app_base_url": getattr(settings, "APP_BASE_URL", ""),
                    }
                },
            )
