import logging

from cloudinary_storage.storage import MediaCloudinaryStorage, RawMediaCloudinaryStorage
from django.conf import settings
from django.core.files.storage import Storage, storages
from django.utils.deconstruct import deconstructible


logger = logging.getLogger("siteguard.runtime")


@deconstructible
class AnalyzerUploadStorage(Storage):
    CLOUDINARY_IMAGE_BACKEND = "cloudinary_storage.storage.MediaCloudinaryStorage"
    CLOUDINARY_RAW_BACKEND = "cloudinary_storage.storage.RawMediaCloudinaryStorage"
    REQUIRED_RESOURCE_TYPE = "raw"

    def _default_backend_path(self):
        return ((getattr(settings, "STORAGES", {}) or {}).get("default", {}) or {}).get("BACKEND", "")

    def _resolve_storage(self):
        default_backend = self._default_backend_path()

        if default_backend in {self.CLOUDINARY_IMAGE_BACKEND, self.CLOUDINARY_RAW_BACKEND}:
            return RawMediaCloudinaryStorage()

        default_storage = storages["default"]
        if isinstance(default_storage, MediaCloudinaryStorage):
            return RawMediaCloudinaryStorage()

        return default_storage

    def _require_storage(self):
        storage = self._resolve_storage()
        resource_type = getattr(storage, "RESOURCE_TYPE", "")
        if isinstance(storage, MediaCloudinaryStorage) and resource_type != self.REQUIRED_RESOURCE_TYPE:
            raise RuntimeError(
                "Analyzer upload storage resolved to a non-raw Cloudinary backend."
            )
        return storage

    def get_debug_metadata(self):
        try:
            storage = self._require_storage()
        except Exception as exc:
            return {
                "storage_class": f"{self.__class__.__module__}.{self.__class__.__name__}",
                "delegate_class": "",
                "resource_type": "",
                "active_media_backend": self._default_backend_path(),
                "available": False,
                "error": str(exc),
            }

        return {
            "storage_class": f"{self.__class__.__module__}.{self.__class__.__name__}",
            "delegate_class": f"{storage.__class__.__module__}.{storage.__class__.__name__}",
            "resource_type": getattr(storage, "RESOURCE_TYPE", ""),
            "active_media_backend": self._default_backend_path(),
            "available": True,
            "error": "",
        }

    def get_delegate_storage(self):
        return self._require_storage()

    def _open(self, name, mode="rb"):
        return self._require_storage().open(name, mode)

    def _save(self, name, content):
        return self._require_storage().save(name, content)

    def delete(self, name):
        return self._require_storage().delete(name)

    def exists(self, name):
        return self._require_storage().exists(name)

    def size(self, name):
        return self._require_storage().size(name)

    def url(self, name):
        return self._require_storage().url(name)

    def path(self, name):
        return self._require_storage().path(name)

    def listdir(self, path):
        return self._require_storage().listdir(path)

    def get_available_name(self, name, max_length=None):
        return self._require_storage().get_available_name(name, max_length=max_length)

    def generate_filename(self, filename):
        return self._require_storage().generate_filename(filename)


def get_uploaded_log_storage():
    return AnalyzerUploadStorage()


def get_uploaded_log_storage_metadata():
    return get_uploaded_log_storage().get_debug_metadata()
