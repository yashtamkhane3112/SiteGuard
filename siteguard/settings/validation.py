from email.utils import parseaddr
from urllib.parse import urlparse

from django.core.exceptions import ImproperlyConfigured


LOCAL_HOST_TOKENS = {
    "*",
    "127.0.0.1",
    "::1",
    "localhost",
    "testserver",
}

DEVELOPMENT_EMAIL_BACKENDS = {
    "django.core.mail.backends.console.EmailBackend",
    "django.core.mail.backends.locmem.EmailBackend",
    "django.core.mail.backends.filebased.EmailBackend",
    "django.core.mail.backends.dummy.EmailBackend",
}


def resolve_email_backend(*, debug, configured_backend, brevo_api_key):
    if configured_backend:
        return configured_backend
    if debug:
        return "django.core.mail.backends.console.EmailBackend"
    if brevo_api_key:
        return "brevo_api"
    return "brevo_api"


def is_secure_secret_key(secret_key):
    key = (secret_key or "").strip()
    return len(key) >= 50 and len(set(key)) >= 5 and not key.startswith("django-insecure-")


def validate_production_configuration(
    *,
    secret_key,
    debug,
    allowed_hosts,
    app_base_url,
    csrf_trusted_origins,
    email_backend,
    email_host,
    email_use_tls,
    email_use_ssl,
    email_timeout,
    brevo_api_key,
    default_from_email,
    cloudinary_storage,
    storages,
    cron_secret,
):
    errors = []

    if debug:
        errors.append("DEBUG must be False in production.")

    if not is_secure_secret_key(secret_key):
        errors.append(
            "SECRET_KEY must be a long random value with at least 50 characters and must not use Django's generated insecure prefix."
        )

    normalized_hosts = [str(host).strip().lower() for host in (allowed_hosts or []) if str(host).strip()]
    if not normalized_hosts:
        errors.append("ALLOWED_HOSTS must contain the deployed hostname.")
    elif any(host in LOCAL_HOST_TOKENS for host in normalized_hosts):
        errors.append("ALLOWED_HOSTS must not include wildcard or local-only hosts in production.")

    if not cron_secret:
        errors.append("CRON_SECRET must be configured in production.")

    parsed_base_url = urlparse((app_base_url or "").strip())
    if parsed_base_url.scheme != "https" or not parsed_base_url.netloc:
        errors.append("APP_BASE_URL must be a valid HTTPS URL in production.")

    if "https://" + parsed_base_url.netloc not in [origin.strip() for origin in (csrf_trusted_origins or [])]:
        errors.append("CSRF_TRUSTED_ORIGINS must include APP_BASE_URL's HTTPS origin in production.")

    if not csrf_trusted_origins:
        errors.append("CSRF_TRUSTED_ORIGINS must include the deployed HTTPS origin.")

    _sender_name, sender_email = parseaddr((default_from_email or "").strip())
    if not sender_email:
        errors.append("DEFAULT_FROM_EMAIL must contain a valid sender email address.")

    if email_use_tls and email_use_ssl:
        errors.append("EMAIL_USE_TLS and EMAIL_USE_SSL cannot both be enabled.")

    if not email_timeout or int(email_timeout) <= 0:
        errors.append("EMAIL_TIMEOUT must be a positive integer.")

    if email_backend in DEVELOPMENT_EMAIL_BACKENDS:
        errors.append("Development email backends are not allowed in production.")

    if email_backend == "django.core.mail.backends.smtp.EmailBackend":
        normalized_host = (email_host or "").strip().lower()
        if "gmail" in normalized_host or "googlemail" in normalized_host:
            errors.append("Gmail SMTP is local-development only and must not be used in production.")
    elif email_backend == "brevo_api":
        if not brevo_api_key:
            errors.append("BREVO_API_KEY is required when EMAIL_BACKEND resolves to brevo_api.")
    else:
        errors.append(f"Unsupported production EMAIL_BACKEND: {email_backend}")

    default_storage_backend = (storages or {}).get("default", {}).get("BACKEND", "")
    if default_storage_backend == "cloudinary_storage.storage.MediaCloudinaryStorage":
        missing_cloudinary = [
            key for key, value in (cloudinary_storage or {}).items()
            if not (value or "").strip()
        ]
        if missing_cloudinary:
            errors.append(
                "Cloudinary media storage requires CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET in production."
            )

    if errors:
        raise ImproperlyConfigured("Production configuration errors:\n- " + "\n- ".join(errors))
