from .base import *  # noqa: F401,F403


DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

MEDIA_ROOT = BASE_DIR / "media"
MEDIA_ROOT.mkdir(parents=True, exist_ok=True)

STORAGES["default"] = {
    "BACKEND": "django.core.files.storage.FileSystemStorage",
}

INTERNAL_IPS = ["127.0.0.1"]
