from decouple import config

from .base import *  # noqa: F401,F403


DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

configured_email_backend = config("EMAIL_BACKEND", default="").strip()
if configured_email_backend:
    EMAIL_BACKEND = configured_email_backend
elif EMAIL_HOST_USER and EMAIL_HOST_PASSWORD:
    EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
else:
    EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"

INTERNAL_IPS = ["127.0.0.1"]
