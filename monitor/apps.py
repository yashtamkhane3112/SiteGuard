from django.apps import AppConfig
from django.conf import settings
import logging


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


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        global _startup_diagnostics_logged
        if not _startup_diagnostics_logged:
            log_ai_startup_diagnostics()
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
