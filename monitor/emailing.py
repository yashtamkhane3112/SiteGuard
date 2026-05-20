import ipaddress
import logging
from email.utils import parseaddr
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode


logger = logging.getLogger("siteguard.email")

DJANGO_FALLBACK_BACKENDS = {
    "django.core.mail.backends.console.EmailBackend",
    "django.core.mail.backends.locmem.EmailBackend",
    "django.core.mail.backends.filebased.EmailBackend",
    "django.core.mail.backends.dummy.EmailBackend",
    "django.core.mail.backends.smtp.EmailBackend",
}


class BrevoAPITransportError(Exception):
    pass


def _get_email_backend():
    return (getattr(settings, "EMAIL_BACKEND", "") or "").strip()


def _using_brevo_api():
    return _get_email_backend() == "brevo_api"


def _using_smtp_fallback():
    return _get_email_backend() == "django.core.mail.backends.smtp.EmailBackend"


def _get_brevo_api_key():
    return (getattr(settings, "BREVO_API_KEY", "") or "").strip()


def _get_brevo_api_url():
    return (getattr(settings, "BREVO_API_URL", "") or "https://api.brevo.com/v3/smtp/email").strip()


def _parse_sender(from_email):
    name, email = parseaddr((from_email or "").strip())
    return {
        "name": (name or getattr(settings, "EMAIL_SENDER_NAME", "") or getattr(settings, "SITE_NAME", "SiteGuard")).strip(),
        "email": email.strip(),
    }


def _build_brevo_recipients(recipients):
    payload = []
    for recipient in recipients:
        name, email = parseaddr((recipient or "").strip())
        if not email:
            continue
        recipient_payload = {"email": email.strip()}
        if name.strip():
            recipient_payload["name"] = name.strip()
        payload.append(recipient_payload)
    return payload


def _brevo_api_is_configured():
    sender = _parse_sender(getattr(settings, "DEFAULT_FROM_EMAIL", "") or "")
    return bool(_get_brevo_api_key() and sender["email"])


def _smtp_is_configured():
    return all(
        (
            getattr(settings, "EMAIL_HOST", "") or "",
            getattr(settings, "EMAIL_HOST_USER", "") or "",
            getattr(settings, "EMAIL_HOST_PASSWORD", "") or "",
            getattr(settings, "DEFAULT_FROM_EMAIL", "") or "",
        )
    )


def _email_transport_is_configured():
    if _using_brevo_api():
        return _brevo_api_is_configured()
    if _using_smtp_fallback():
        return _smtp_is_configured()
    return bool(_get_email_backend() and getattr(settings, "DEFAULT_FROM_EMAIL", ""))


def _get_email_provider():
    if _using_brevo_api():
        return "brevo_api"
    if _using_smtp_fallback():
        host = (getattr(settings, "EMAIL_HOST", "") or "").strip().lower()
        if "brevo" in host:
            return "brevo_smtp"
        if "gmail" in host or "googlemail" in host:
            return "gmail_smtp"
        if not host:
            return "smtp"
        return "custom_smtp"
    if _get_email_backend():
        return "django_backend"
    return "unknown"


def _build_brevo_payload(*, subject, text_body, html_body, recipients, from_email):
    payload = {
        "sender": _parse_sender(from_email),
        "to": _build_brevo_recipients(recipients),
        "subject": subject,
    }
    if html_body:
        payload["htmlContent"] = html_body
    elif text_body:
        payload["textContent"] = text_body
    return payload


def _send_via_brevo_api(*, subject, text_body, html_body, recipients, from_email, timeout):
    payload = _build_brevo_payload(
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        recipients=recipients,
        from_email=from_email,
    )
    response = requests.post(
        _get_brevo_api_url(),
        headers={
            "accept": "application/json",
            "api-key": _get_brevo_api_key(),
            "content-type": "application/json",
        },
        json=payload,
        timeout=timeout,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        response_text = (response.text or "").strip()
        raise BrevoAPITransportError(
            f"Brevo API returned HTTP {response.status_code}: {response_text[:500]}"
        ) from exc

    response_payload = response.json() if response.content else {}
    return response_payload.get("messageId", "")


def _clean_subject(subject):
    return " ".join((subject or "").splitlines()).strip()


def prefix_email_subject(subject):
    cleaned_subject = _clean_subject(subject)
    prefix = getattr(settings, "EMAIL_SUBJECT_PREFIX", "") or ""
    if not prefix:
        return cleaned_subject
    if cleaned_subject.startswith(prefix):
        return cleaned_subject
    return f"{prefix}{cleaned_subject}"


def get_sender_email_address():
    return _parse_sender(getattr(settings, "DEFAULT_FROM_EMAIL", "") or "")["email"]


def get_support_email():
    return (getattr(settings, "SUPPORT_EMAIL", "") or get_sender_email_address()).strip()


def get_canonical_base_url():
    return (getattr(settings, "CANONICAL_BASE_URL", "") or getattr(settings, "APP_BASE_URL", "") or "").rstrip("/")


def _is_local_hostname(hostname):
    normalized = (hostname or "").strip().lower().strip("[]")
    if not normalized:
        return False
    if normalized in {"localhost", "127.0.0.1", "::1", "testserver"} or normalized.endswith(".local"):
        return True
    try:
        ip_obj = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return any((
        ip_obj.is_private,
        ip_obj.is_loopback,
        ip_obj.is_link_local,
        ip_obj.is_reserved,
    ))


def is_local_base_url(base_url):
    parsed = urlparse((base_url or "").strip())
    return _is_local_hostname(parsed.hostname)


def get_local_development_base_url():
    configured_base_url = get_canonical_base_url()
    if configured_base_url and is_local_base_url(configured_base_url):
        return configured_base_url
    return "http://127.0.0.1:8000"


def get_email_base_url(request=None):
    if getattr(settings, "DEBUG", False):
        if request is not None:
            return request.build_absolute_uri("/").rstrip("/")
        return get_local_development_base_url()

    canonical_base_url = get_canonical_base_url()
    if canonical_base_url:
        return canonical_base_url
    if request is not None:
        return request.build_absolute_uri("/").rstrip("/")
    return ""


def build_password_reset_preview_url(user, base_url):
    normalized_base_url = (base_url or "").rstrip("/")
    reset_path = reverse(
        "password_reset_confirm",
        kwargs={
            "uidb64": urlsafe_base64_encode(force_bytes(user.pk)),
            "token": default_token_generator.make_token(user),
        },
    )
    if normalized_base_url:
        return f"{normalized_base_url}{reset_path}"
    return reset_path


def build_password_reset_email_options(request=None):
    options = {
        "from_email": getattr(settings, "DEFAULT_FROM_EMAIL", None),
        "html_email_template_name": "registration/password_reset_email.html",
        "extra_email_context": {
            "site_name": getattr(settings, "SITE_NAME", "SiteGuard"),
            "support_email": get_support_email(),
            "email_subject_prefix": getattr(settings, "EMAIL_SUBJECT_PREFIX", ""),
        },
    }
    base_url = get_email_base_url(request=request)
    if base_url:
        parsed = urlparse(base_url)
        if parsed.netloc:
            options["domain_override"] = parsed.netloc
        if parsed.scheme:
            options["use_https"] = parsed.scheme == "https"
        options["extra_email_context"]["resolved_base_url"] = base_url
    return options


def get_email_diagnostics():
    return {
        "backend": _get_email_backend(),
        "provider": _get_email_provider(),
        "transport": "https_api" if _using_brevo_api() else "django_backend",
        "api_url": _get_brevo_api_url() if _using_brevo_api() else "",
        "api_key_present": bool(_get_brevo_api_key()),
        "smtp_provider": _get_email_provider(),
        "smtp_host": getattr(settings, "EMAIL_HOST", "") or "",
        "port": getattr(settings, "EMAIL_PORT", None),
        "use_tls": getattr(settings, "EMAIL_USE_TLS", False),
        "use_ssl": getattr(settings, "EMAIL_USE_SSL", False),
        "timeout": getattr(settings, "EMAIL_TIMEOUT", None),
        "configured": _email_transport_is_configured(),
        "host_user_present": bool(getattr(settings, "EMAIL_HOST_USER", "")),
        "host_password_present": bool(getattr(settings, "EMAIL_HOST_PASSWORD", "")),
        "brevo_login_present": bool(getattr(settings, "BREVO_SMTP_LOGIN", "")),
        "brevo_password_present": bool(getattr(settings, "BREVO_SMTP_PASSWORD", "")),
        "smtp_login_source": "email_host_user",
        "smtp_password_source": "email_host_password",
        "sender_email": get_sender_email_address(),
        "from_email": getattr(settings, "DEFAULT_FROM_EMAIL", ""),
        "base_url": get_canonical_base_url(),
        "using_smtp": _using_smtp_fallback(),
        "using_brevo_api": _using_brevo_api(),
    }


def send_siteguard_email(
    *,
    subject,
    text_body,
    recipients,
    html_body=None,
    from_email=None,
    log_context=None,
    raise_on_error=False,
):
    recipient_list = [recipient.strip() for recipient in (recipients or []) if recipient and recipient.strip()]
    email_diagnostics = get_email_diagnostics()
    if not recipient_list:
        logger.warning(
            "Email send skipped because no recipients were provided.",
            extra={"email_context": {**(log_context or {}), "diagnostics": email_diagnostics}},
        )
        return False

    if not email_diagnostics["configured"]:
        provider_label = "Brevo API" if _using_brevo_api() else "email backend"
        logger.warning(
            f"{provider_label} email send skipped because production email settings are incomplete.",
            extra={
                "email_context": {
                    "recipients": recipient_list,
                    **(log_context or {}),
                    "diagnostics": email_diagnostics,
                }
            },
        )
        return False

    final_subject = prefix_email_subject(subject)
    final_from_email = from_email or getattr(settings, "DEFAULT_FROM_EMAIL", "")

    try:
        if _using_brevo_api():
            message_id = _send_via_brevo_api(
                subject=final_subject,
                text_body=text_body,
                html_body=html_body,
                recipients=recipient_list,
                from_email=final_from_email,
                timeout=getattr(settings, "EMAIL_TIMEOUT", None),
            )
        else:
            message = EmailMultiAlternatives(
                subject=final_subject,
                body=text_body,
                from_email=final_from_email,
                to=recipient_list,
            )
            if html_body:
                message.attach_alternative(html_body, "text/html")
            message.send(fail_silently=False)
            message_id = ""
        logger.info(
            "Email sent successfully.",
            extra={
                "email_context": {
                    "subject": final_subject,
                    "recipients": recipient_list,
                    "provider_message_id": message_id,
                    **(log_context or {}),
                    "diagnostics": email_diagnostics,
                }
            },
        )
        return True
    except Exception as exc:
        warning_message = None
        if isinstance(exc, requests.Timeout):
            warning_message = "Brevo API request timed out before the provider completed the send."
        elif isinstance(exc, BrevoAPITransportError):
            warning_message = "Brevo API rejected the email request. Verify the API key, sender identity, and request payload."
        elif isinstance(exc, requests.RequestException):
            warning_message = "Brevo API request failed. Verify Render egress access, HTTPS connectivity, and provider availability."
        elif isinstance(exc, TimeoutError):
            warning_message = "Email request timed out before the provider completed the send."
        email_diagnostics["exception_type"] = exc.__class__.__name__
        email_diagnostics["exception_message"] = str(exc)

        logger.exception(
            "Email send failed.",
            extra={
                "email_context": {
                    "subject": final_subject,
                    "recipients": recipient_list,
                    **(log_context or {}),
                    "diagnostics": email_diagnostics,
                    "warning": warning_message or "",
                }
            },
        )
        if raise_on_error:
            raise
        return False


def render_email_template(template_name, context):
    return render_to_string(template_name, context)
