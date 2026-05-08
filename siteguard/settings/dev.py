from .base import *  # noqa: F401,F403


DEBUG = True
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"

INTERNAL_IPS = ["127.0.0.1"]
