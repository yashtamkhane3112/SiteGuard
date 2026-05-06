import socket
import ssl
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import Alert, Incident, IncidentEvent, MonitorLog


def get_site_status(log):
    if not log:
        return "DOWN"

    if getattr(log, "status", None) == "DOWN":
        return "DOWN"

    if log.response_time is None:
        return "DOWN"

    if log.response_time > 2000:
        return "SLOW"

    return "UP"


def get_latest_logs_by_website(logs):
    latest_logs = {}

    for log in logs:
        if log.website_id not in latest_logs:
            latest_logs[log.website_id] = log

    return latest_logs


def normalize_domain_display(url):
    raw_url = (url or '').strip()
    if not raw_url:
        return ''

    parsed = urlparse(raw_url if '://' in raw_url else f'https://{raw_url}')
    domain = (parsed.netloc or parsed.path or '').strip().lower()
    domain = domain.rstrip('/')
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain


def get_favicon_url(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path.split("/")[0]
    return f"https://www.google.com/s2/favicons?domain={domain}&sz=64"


def check_ssl_status(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path.split("/")[0]
        if not hostname:
            return "Invalid"

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return "Valid"
    except Exception:
        return "Invalid"


def get_incident_title(status):
    if status == MonitorLog.STATUS_DOWN:
        return "Complete Outage"
    if status == MonitorLog.STATUS_SLOW:
        return "High Response Times"
    return "SSL Certificate Warning"


def get_incident_type(status):
    if status == MonitorLog.STATUS_DOWN:
        return Incident.TYPE_OUTAGE
    if status == MonitorLog.STATUS_SLOW:
        return Incident.TYPE_PERFORMANCE
    return Incident.TYPE_SSL


def _format_response_time(response_time):
    if response_time is None:
        return "No response"
    return f"{round(response_time, 2)}ms"


def get_numeric_response_time(response_time, default=0):
    if response_time is None:
        return default
    try:
        return round(float(response_time), 2)
    except (TypeError, ValueError):
        return default


def get_valid_response_times(logs):
    return [
        float(log.response_time)
        for log in logs
        if getattr(log, "response_time", None) is not None
    ]


def get_incident_title_for_type(incident_type):
    title_map = {
        Incident.TYPE_OUTAGE: "Complete Outage",
        Incident.TYPE_PERFORMANCE: "High Response Times",
        Incident.TYPE_SSL: "SSL Certificate Warning",
    }
    return title_map.get(incident_type, "Monitoring Incident")


def normalize_incident(incident, website=None):
    expected_website = website or incident.website
    update_fields = []

    if incident.website_id != expected_website.id:
        incident.website = expected_website
        update_fields.append('website')

    if incident.is_resolved:
        if incident.status != Incident.STATUS_RESOLVED:
            incident.status = Incident.STATUS_RESOLVED
            update_fields.append('status')
        if incident.resolved_at is None:
            incident.resolved_at = incident.updated_at
            update_fields.append('resolved_at')
    else:
        expected_title = get_incident_title_for_type(incident.incident_type)
        if incident.title != expected_title:
            incident.title = expected_title
            update_fields.append('title')
        if incident.status == Incident.STATUS_RESOLVED:
            incident.status = (
                Incident.STATUS_SLOW if incident.incident_type == Incident.TYPE_SSL
                else Incident.STATUS_DOWN if incident.incident_type == Incident.TYPE_OUTAGE
                else Incident.STATUS_SLOW
            )
            update_fields.append('status')

    if incident.latest_response_time is not None:
        normalized_response_time = get_numeric_response_time(incident.latest_response_time, default=None)
        if normalized_response_time != incident.latest_response_time:
            incident.latest_response_time = normalized_response_time
            update_fields.append('latest_response_time')

    if update_fields:
        incident.save(update_fields=update_fields)

    return incident


def create_incident_event(incident, event_type, message):
    normalize_incident(incident)
    last_event = incident.events.order_by('-created_at', '-id').first()
    if last_event and last_event.event_type == event_type and last_event.message == message:
        return last_event

    return IncidentEvent.objects.create(
        incident=incident,
        event_type=event_type,
        message=message,
    )


def send_alert_email(alert, recovery_time=None):
    website = alert.website
    incident = alert.incident
    incident_start = incident.started_at if incident else alert.created_at
    response_time = _format_response_time(alert.response_time)

    if alert.alert_type == Alert.TYPE_DOWN:
        subject = f"SiteGuard Alert: {website.url} is DOWN"
    elif alert.alert_type == Alert.TYPE_SLOW:
        subject = f"SiteGuard Warning: {website.url} response times degraded"
    elif alert.alert_type == Alert.TYPE_RECOVERY:
        subject = f"SiteGuard Recovery: {website.url} is operational again"
    else:
        subject = f"SiteGuard SSL Alert: {website.url} SSL validation failed"

    lines = [
        f"Website: {website.url}",
        f"Alert Type: {alert.alert_type}",
        f"Status: {alert.alert_type}",
        f"Response Time: {response_time}",
        f"Incident Started: {incident_start:%Y-%m-%d %H:%M:%S}",
    ]
    if recovery_time is not None:
        lines.append(f"Recovery Time: {recovery_time:%Y-%m-%d %H:%M:%S}")
    lines.append("")
    lines.append(alert.message)

    send_mail(
        subject,
        "\n".join(lines),
        getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        [website.user.email],
        fail_silently=False,
    )


def create_or_update_alert(website, alert_type, message, incident=None, response_time=None, recovery_time=None):
    if incident is not None:
        normalize_incident(incident)
        website = incident.website

    if not website.alerts_enabled:
        return None

    sent_to = website.user.email if website.email_notifications and website.user.email else ''
    alert = Alert.objects.filter(
        website=website,
        incident=incident,
        alert_type=alert_type,
        is_read=False,
    ).order_by('-created_at', '-id').first()

    if alert and alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING} and alert.message == message:
        if response_time is not None and alert.response_time != response_time:
            alert.response_time = response_time
            alert.save(update_fields=['response_time'])
        return alert

    if alert is None or alert.status == Alert.STATUS_FAILED or alert.message != message:
        alert = Alert.objects.create(
            website=website,
            incident=incident,
            alert_type=alert_type,
            status=Alert.STATUS_PENDING,
            message=message,
            sent_to=sent_to,
            response_time=get_numeric_response_time(response_time, default=None),
        )

    if not sent_to:
        alert.status = Alert.STATUS_SENT
        alert.save(update_fields=['status'])
        return alert

    try:
        send_alert_email(alert, recovery_time=recovery_time)
        alert.status = Alert.STATUS_SENT
        alert.sent_to = sent_to
        alert.save(update_fields=['status', 'sent_to'])
    except Exception as exc:
        alert.status = Alert.STATUS_FAILED
        alert.message = f"{message}\n\nDelivery failure: {exc}"
        alert.save(update_fields=['status', 'message'])

    return alert


def cleanup_monitoring_state(user=None):
    incident_filter = {}
    if user is not None:
        incident_filter['website__user'] = user

    with transaction.atomic():
        incidents = list(
            Incident.objects.select_related('website').filter(**incident_filter).order_by(
                'website_id', 'incident_type', '-started_at', '-created_at'
            )
        )

        active_seen = set()
        for incident in incidents:
            normalize_incident(incident)
            incident_key = (incident.website_id, incident.incident_type)
            if not incident.is_resolved:
                if incident_key in active_seen:
                    incident.is_resolved = True
                    incident.status = Incident.STATUS_RESOLVED
                    incident.resolved_at = incident.resolved_at or incident.updated_at
                    incident.save(update_fields=['is_resolved', 'status', 'resolved_at'])
                    create_incident_event(
                        incident,
                        IncidentEvent.TYPE_RESOLVED,
                        "Duplicate active incident automatically closed during integrity cleanup.",
                    )
                else:
                    active_seen.add(incident_key)

        alert_filter = {}
        if user is not None:
            alert_filter['website__user'] = user

        alerts = list(
            Alert.objects.select_related('website', 'incident').filter(**alert_filter).order_by(
                'website_id', 'alert_type', '-created_at', '-id'
            )
        )
        alert_seen = set()

        for alert in alerts:
            update_fields = []
            if alert.incident_id is not None and alert.website_id != alert.incident.website_id:
                alert.website = alert.incident.website
                update_fields.append('website')

            if alert.response_time is not None:
                normalized_response_time = get_numeric_response_time(alert.response_time, default=None)
                if normalized_response_time != alert.response_time:
                    alert.response_time = normalized_response_time
                    update_fields.append('response_time')

            alert_key = (
                alert.website_id,
                alert.incident_id,
                alert.alert_type,
                alert.status,
                alert.is_read,
            )
            if (
                alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING}
                and not alert.is_read
                and alert_key in alert_seen
            ):
                alert.is_read = True
                alert.read_at = alert.read_at or alert.created_at
                update_fields.extend(['is_read', 'read_at'])
            else:
                alert_seen.add(alert_key)

            if update_fields:
                alert.save(update_fields=update_fields)


def resolve_incident(incident, current_log, create_recovery_alert=False, message=None):
    incident.status = Incident.STATUS_RESOLVED
    incident.is_resolved = True
    incident.resolved_at = current_log.checked_at
    incident.latest_response_time = current_log.response_time
    incident.save(
        update_fields=['status', 'is_resolved', 'resolved_at', 'latest_response_time', 'updated_at']
    )
    create_incident_event(
        incident,
        IncidentEvent.TYPE_RESOLVED,
        message or f"Automated monitoring confirmed recovery at {_format_response_time(current_log.response_time)}.",
    )

    if create_recovery_alert:
        create_or_update_alert(
            incident.website,
            Alert.TYPE_RECOVERY,
            f"{incident.website.url} recovered and is operational again.",
            incident=incident,
            response_time=current_log.response_time,
            recovery_time=current_log.checked_at,
        )


def sync_incident_state(website, previous_log, current_log):
    previous_status = get_site_status(previous_log)
    current_status = get_site_status(current_log)
    active_incidents = Incident.objects.filter(
        website=website,
        is_resolved=False,
    ).exclude(incident_type=Incident.TYPE_SSL).order_by('-started_at')

    if current_status == MonitorLog.STATUS_UP:
        for incident in active_incidents:
            resolve_incident(incident, current_log, create_recovery_alert=True)
        return

    if current_status not in {MonitorLog.STATUS_DOWN, MonitorLog.STATUS_SLOW}:
        return

    incident_type = get_incident_type(current_status)
    active_incident = active_incidents.filter(incident_type=incident_type).first()

    for incident in active_incidents.exclude(pk=active_incident.pk if active_incident else None):
        resolve_incident(
            incident,
            current_log,
            create_recovery_alert=False,
            message=f"Incident automatically closed after status changed to {current_status}.",
        )

    if active_incident is None:
        active_incident = Incident.objects.create(
            website=website,
            title=get_incident_title(current_status),
            incident_type=incident_type,
            status=current_status,
            started_at=current_log.checked_at,
            latest_response_time=current_log.response_time,
        )
        detail = (
            f"Automated monitoring detected {website.url} as {current_status} "
            f"at {_format_response_time(current_log.response_time)}."
        )
        create_incident_event(active_incident, IncidentEvent.TYPE_DETECTED, detail)
        if (
            current_status == MonitorLog.STATUS_DOWN
            or current_log.response_time is None
            or current_log.response_time > get_monitor_threshold(website)
        ):
            create_or_update_alert(
                website,
                Alert.TYPE_DOWN if current_status == MonitorLog.STATUS_DOWN else Alert.TYPE_SLOW,
                detail,
                incident=active_incident,
                response_time=current_log.response_time,
            )
        return

    active_incident.status = current_status
    active_incident.title = get_incident_title(current_status)
    active_incident.latest_response_time = current_log.response_time
    active_incident.save(update_fields=['status', 'title', 'latest_response_time', 'updated_at'])

    if previous_status != current_status:
        create_incident_event(
            active_incident,
            IncidentEvent.TYPE_MONITORING,
            f"Status changed from {previous_status} to {current_status} at {_format_response_time(current_log.response_time)}.",
        )


def sync_ssl_state(website, current_log, ssl_status):
    if ssl_status not in {"Valid", "Invalid"}:
        return

    active_ssl_incident = Incident.objects.filter(
        website=website,
        incident_type=Incident.TYPE_SSL,
        is_resolved=False,
    ).order_by('-started_at').first()

    if ssl_status == "Valid":
        if active_ssl_incident is not None:
            resolve_incident(
                active_ssl_incident,
                current_log,
                create_recovery_alert=True,
                message="SSL validation recovered and certificate checks are passing again.",
            )
        return

    if active_ssl_incident is None:
        active_ssl_incident = Incident.objects.create(
            website=website,
            title="SSL Certificate Warning",
            incident_type=Incident.TYPE_SSL,
            status=Incident.STATUS_SLOW,
            started_at=current_log.checked_at,
            latest_response_time=current_log.response_time,
        )
        create_incident_event(
            active_ssl_incident,
            IncidentEvent.TYPE_DETECTED,
            f"SSL validation failed for {website.url} during automated monitoring.",
        )
        create_or_update_alert(
            website,
            Alert.TYPE_SSL,
            f"SSL validation failed for {website.url}.",
            incident=active_ssl_incident,
            response_time=current_log.response_time,
        )
        return

    active_ssl_incident.latest_response_time = current_log.response_time
    active_ssl_incident.save(update_fields=['latest_response_time', 'updated_at'])


def get_monitor_threshold(website):
    return getattr(website, 'slow_alert_threshold', 2000) or 2000


def run_single_check(website, timeout=5):
    url = website.url
    if not url.startswith("http"):
        url = "https://" + url

    previous_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
    ssl_status = None

    try:
        response = requests.get(url, timeout=timeout)
        response_time_ms = response.elapsed.total_seconds() * 1000
        ssl_status = check_ssl_status(url)

        if 200 <= response.status_code < 400:
            status = (
                MonitorLog.STATUS_SLOW
                if response_time_ms > 2000
                else MonitorLog.STATUS_UP
            )
        else:
            status = MonitorLog.STATUS_DOWN

        log = MonitorLog.objects.create(
            website=website,
            status=status,
            response_time=round(response_time_ms, 2),
        )
        sync_incident_state(website, previous_log, log)
        sync_ssl_state(website, log, ssl_status)
        return log, response
    except Exception:
        log = MonitorLog.objects.create(
            website=website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        sync_incident_state(website, previous_log, log)
        return log, None


def get_site_snapshot(log):
    response_time = 0
    if log and log.response_time is not None:
        response_time = round(log.response_time, 2)

    return {
        "status": get_site_status(log),
        "response_time": response_time,
        "last_checked": log.checked_at if log else None,
    }
