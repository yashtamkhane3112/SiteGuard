import logging
import ipaddress
import smtplib
from urllib.parse import urlparse

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMultiAlternatives, get_connection
from django.urls import reverse
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes


logger = logging.getLogger("siteguard.email")


def _smtp_is_configured():
    backend = getattr(settings, "EMAIL_BACKEND", "") or ""
    if backend != "django.core.mail.backends.smtp.EmailBackend":
        return bool(backend and getattr(settings, "DEFAULT_FROM_EMAIL", ""))
    return all(
        (
            getattr(settings, "EMAIL_HOST", "") or "",
            getattr(settings, "EMAIL_HOST_USER", "") or "",
            getattr(settings, "EMAIL_HOST_PASSWORD", "") or "",
            getattr(settings, "DEFAULT_FROM_EMAIL", "") or "",
        )
    )


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
    sender = getattr(settings, "DEFAULT_FROM_EMAIL", "") or ""
    if "<" in sender and ">" in sender:
        return sender.rsplit("<", 1)[-1].split(">", 1)[0].strip()
    return sender.strip()


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
    backend = getattr(settings, "EMAIL_BACKEND", "") or ""
    host = getattr(settings, "EMAIL_HOST", "") or ""
    using_smtp = backend == "django.core.mail.backends.smtp.EmailBackend"
    return {
        "backend": backend,
        "smtp_host": host,
        "port": getattr(settings, "EMAIL_PORT", None),
        "use_tls": getattr(settings, "EMAIL_USE_TLS", False),
        "use_ssl": getattr(settings, "EMAIL_USE_SSL", False),
        "timeout": getattr(settings, "EMAIL_TIMEOUT", None),
        "configured": _smtp_is_configured(),
        "host_user_present": bool(getattr(settings, "EMAIL_HOST_USER", "")),
        "host_password_present": bool(getattr(settings, "EMAIL_HOST_PASSWORD", "")),
        "sender_email": get_sender_email_address(),
        "from_email": getattr(settings, "DEFAULT_FROM_EMAIL", ""),
        "base_url": get_canonical_base_url(),
        "using_smtp": using_smtp,
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

    if email_diagnostics["using_smtp"] and not email_diagnostics["configured"]:
        logger.warning(
            "SMTP email send skipped because production email settings are incomplete.",
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
    connection = get_connection(timeout=getattr(settings, "EMAIL_TIMEOUT", None))
    message = EmailMultiAlternatives(
        subject=final_subject,
        body=text_body,
        from_email=final_from_email,
        to=recipient_list,
        connection=connection,
    )
    if html_body:
        message.attach_alternative(html_body, "text/html")

    try:
        message.send(fail_silently=False)
        logger.info(
            "Email sent successfully.",
            extra={
                "email_context": {
                    "subject": final_subject,
                    "recipients": recipient_list,
                    **(log_context or {}),
                    "diagnostics": email_diagnostics,
                }
            },
        )
        return True
    except Exception as exc:
        warning_message = None
        if isinstance(exc, smtplib.SMTPAuthenticationError):
            warning_message = "SMTP authentication failed. Gmail SMTP usually requires an app password and a verified sender."
        elif isinstance(exc, smtplib.SMTPConnectError):
            warning_message = "SMTP connection failed. Verify Render egress access, SMTP host, port, and TLS settings."
        elif isinstance(exc, TimeoutError):
            warning_message = "SMTP request timed out before the provider completed the send."
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
