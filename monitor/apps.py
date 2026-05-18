from django.apps import AppConfig
from django.conf import settings
import logging


class MonitorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'monitor'

    def ready(self):
        if getattr(settings, "DEBUG", False):
            return

        storage_backend = settings.STORAGES.get("default", {}).get("BACKEND", "")
        if storage_backend == "django.core.files.storage.FileSystemStorage":
            logging.getLogger("siteguard.runtime").warning(
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
