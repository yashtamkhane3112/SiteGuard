import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone as dt_timezone
from time import perf_counter
from urllib.parse import quote, unquote, urlparse

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import Alert, Incident, IncidentEvent, MonitorLog, UserProfile, Website

try:
    import dns.resolver as dns_resolver
except Exception:  # pragma: no cover - optional dependency
    dns_resolver = None


UTILITY_TIMEOUT = 5
UTILITY_SLOW_THRESHOLD_MS = 2000
SECURITY_HEADERS = {
    'strict-transport-security': 'Missing HSTS',
    'x-frame-options': 'Missing clickjacking protection',
    'x-content-type-options': 'Missing MIME sniffing protection',
    'content-security-policy': 'Missing CSP',
    'referrer-policy': 'Missing referrer policy',
}


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


def _has_invalid_percent_encoding(value):
    return bool(re.search(r'%(?![0-9A-Fa-f]{2})', value or ''))


def safe_url_encode(value):
    text = value or ''
    return {
        'value': text,
        'result': quote(text, safe=''),
        'success': True,
        'error': '',
    }


def safe_url_decode(value):
    text = value or ''
    if _has_invalid_percent_encoding(text):
        return {
            'value': text,
            'result': '',
            'success': False,
            'error': 'Invalid percent-encoding sequence.',
        }

    return {
        'value': text,
        'result': unquote(text),
        'success': True,
        'error': '',
    }


def _extract_hostname(raw_value):
    value = (raw_value or '').strip()
    if not value:
        raise ValidationError('Enter a domain to inspect.')

    candidate = value if '://' in value else f'https://{value}'
    parsed = urlparse(candidate)
    if parsed.scheme not in {'http', 'https'}:
        raise ValidationError('Only HTTP and HTTPS domains are allowed.')

    hostname = (parsed.hostname or '').strip().rstrip('.')
    if not hostname:
        raise ValidationError('Enter a valid domain.')
    return hostname


def _is_blocked_host(hostname):
    lowered = hostname.lower()
    if lowered in {'localhost', 'localhost.localdomain'} or lowered.endswith('.local'):
        return True

    try:
        ip_obj = ipaddress.ip_address(lowered)
    except ValueError:
        return False

    blocked_flags = (
        ip_obj.is_private,
        ip_obj.is_loopback,
        ip_obj.is_reserved,
        ip_obj.is_link_local,
        ip_obj.is_multicast,
        ip_obj.is_unspecified,
    )
    return any(blocked_flags)


def _is_blocked_ip_value(value):
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return False

    return any((
        ip_obj.is_private,
        ip_obj.is_loopback,
        ip_obj.is_reserved,
        ip_obj.is_link_local,
        ip_obj.is_multicast,
        ip_obj.is_unspecified,
    ))


def normalize_utility_domain(raw_value):
    hostname = _extract_hostname(raw_value)

    try:
        ascii_hostname = hostname.encode('idna').decode('ascii').lower()
    except UnicodeError as exc:
        raise ValidationError('Domain contains invalid Unicode characters.') from exc

    if _is_blocked_host(ascii_hostname):
        raise ValidationError('Local, private, and reserved hosts are not allowed.')

    if '.' not in ascii_hostname:
        raise ValidationError('Enter a valid public domain.')

    if re.search(r'[^a-z0-9.-]', ascii_hostname):
        raise ValidationError('Enter a valid public domain.')

    return ascii_hostname


def resolve_hostname(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def fetch_ssl_details(domain, timeout=UTILITY_TIMEOUT):
    result = {
        'valid': False,
        'issuer': '',
        'expiry_date': '',
        'days_remaining': None,
        'error': '',
    }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as wrapped:
                certificate = wrapped.getpeercert()
    except ssl.SSLError as exc:
        result['error'] = str(exc)
        return result
    except Exception as exc:
        result['error'] = str(exc)
        return result

    issuer_parts = []
    for item in certificate.get('issuer', []):
        for key, value in item:
            if key.lower() in {'organizationname', 'commonname'} and value:
                issuer_parts.append(value)
    not_after = certificate.get('notAfter')

    expiry_date = ''
    days_remaining = None
    if not_after:
        try:
            expires_at = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=dt_timezone.utc)
            expiry_date = expires_at.strftime('%Y-%m-%d')
            days_remaining = max((expires_at - datetime.now(dt_timezone.utc)).days, 0)
        except ValueError:
            expiry_date = not_after

    result.update({
        'valid': True,
        'issuer': ', '.join(issuer_parts),
        'expiry_date': expiry_date,
        'days_remaining': days_remaining,
    })
    return result


def lookup_dns_records(domain):
    records = {'A': [], 'MX': [], 'NS': [], 'TXT': []}
    if dns_resolver is None:
        ip_address = resolve_hostname(domain)
        if ip_address:
            records['A'] = [ip_address]
        return records

    query_types = ('A', 'MX', 'NS', 'TXT')
    for record_type in query_types:
        try:
            answers = dns_resolver.resolve(domain, record_type, lifetime=UTILITY_TIMEOUT)
            if record_type == 'MX':
                records[record_type] = [
                    f"{answer.preference} {str(answer.exchange).rstrip('.')}" for answer in answers
                ]
            elif record_type == 'TXT':
                txt_values = []
                for answer in answers:
                    if hasattr(answer, 'strings'):
                        txt_values.append(''.join(part.decode('utf-8', errors='ignore') for part in answer.strings))
                    else:
                        txt_values.append(str(answer).strip('"'))
                records[record_type] = txt_values
            else:
                records[record_type] = [str(answer).rstrip('.') for answer in answers]
        except Exception:
            records[record_type] = []
    return records


def inspect_headers(headers, ssl_valid):
    normalized = {str(key).lower(): str(value) for key, value in (headers or {}).items()}
    missing_security_headers = [
        message for header, message in SECURITY_HEADERS.items() if not normalized.get(header)
    ]
    weak_configurations = []
    if normalized.get('server'):
        weak_configurations.append(f"Server header exposed: {normalized['server']}")
    if normalized.get('x-powered-by'):
        weak_configurations.append(f"X-Powered-By exposed: {normalized['x-powered-by']}")
    if ssl_valid and normalized.get('strict-transport-security') is None:
        weak_configurations.append('HTTPS is enabled but HSTS is missing.')

    return {
        'server': normalized.get('server', ''),
        'content_type': normalized.get('content-type', ''),
        'cache_control': normalized.get('cache-control', ''),
        'x_frame_options': normalized.get('x-frame-options', ''),
        'strict_transport_security': normalized.get('strict-transport-security', ''),
        'security_headers': {header: normalized.get(header, '') for header in SECURITY_HEADERS},
        'missing_security_headers': missing_security_headers,
        'weak_configurations': weak_configurations,
    }


def analyze_domain(domain, timeout=UTILITY_TIMEOUT):
    result = {
        'input': domain or '',
        'domain': '',
        'url': '',
        'ip_address': '',
        'reachable': False,
        'ssl_valid': False,
        'response_time': None,
        'status': None,
        'error_message': '',
        'nameserver_count': 0,
        'security_state': 'Unreachable',
        'dns_records': {'A': [], 'MX': [], 'NS': [], 'TXT': []},
        'ssl_details': {
            'valid': False,
            'issuer': '',
            'expiry_date': '',
            'days_remaining': None,
            'error': '',
        },
        'headers': {
            'server': '',
            'content_type': '',
            'cache_control': '',
            'x_frame_options': '',
            'strict_transport_security': '',
            'security_headers': {},
            'missing_security_headers': [],
            'weak_configurations': [],
        },
        'latency': {
            'response_time': None,
            'status_code': None,
            'reachable': False,
            'state': 'DOWN',
            'is_slow': False,
        },
    }

    try:
        normalized_domain = normalize_utility_domain(domain)
    except ValidationError as exc:
        result['error_message'] = exc.messages[0] if hasattr(exc, 'messages') else str(exc)
        return result

    result['domain'] = normalized_domain
    result['url'] = f'https://{normalized_domain}'
    result['ip_address'] = resolve_hostname(normalized_domain) or ''
    if result['ip_address'] and _is_blocked_ip_value(result['ip_address']):
        result['ip_address'] = ''
        result['error_message'] = 'Resolved address is private or reserved.'
        return result

    dns_records = lookup_dns_records(normalized_domain)
    result['dns_records'] = dns_records
    result['nameserver_count'] = len(dns_records.get('NS', []))
    if not result['ip_address'] and dns_records.get('A'):
        result['ip_address'] = dns_records['A'][0]

    ssl_details = fetch_ssl_details(normalized_domain, timeout=timeout)
    result['ssl_details'] = ssl_details
    result['ssl_valid'] = ssl_details['valid']

    try:
        started = perf_counter()
        response = requests.get(
            result['url'],
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'SiteGuard Utilities/1.0'},
            stream=True,
        )
        response_time_ms = round((perf_counter() - started) * 1000, 2)
        headers_info = inspect_headers(response.headers, ssl_details['valid'])

        result['reachable'] = True
        result['status'] = response.status_code
        result['response_time'] = response_time_ms
        result['headers'] = headers_info
        result['latency'] = {
            'response_time': response_time_ms,
            'status_code': response.status_code,
            'reachable': True,
            'state': 'SLOW' if response_time_ms > UTILITY_SLOW_THRESHOLD_MS else 'UP',
            'is_slow': response_time_ms > UTILITY_SLOW_THRESHOLD_MS,
        }
        if ssl_details['valid'] and not headers_info['missing_security_headers'] and not headers_info['weak_configurations']:
            result['security_state'] = 'Secure'
        elif ssl_details['valid'] and response.status_code < 500:
            result['security_state'] = 'Warning'
        else:
            result['security_state'] = 'Risk'
    except requests.Timeout:
        result['error_message'] = 'Request timed out.'
        result['latency']['state'] = 'SLOW'
        result['security_state'] = 'Timeout'
    except requests.RequestException as exc:
        result['error_message'] = str(exc)
        result['security_state'] = 'Unreachable'

    if not result['reachable'] and not result['error_message'] and not result['ip_address']:
        result['error_message'] = 'Domain could not be resolved.'

    return result


def is_domain_monitored(user, domain):
    if not getattr(user, 'is_authenticated', False) or not domain:
        return False

    normalized_url = Website.normalize_url(domain)
    return Website.objects.filter(user=user, url=normalized_url).exists()


def get_or_create_user_profile(user):
    profile, _created = UserProfile.objects.get_or_create(user=user)
    return profile


def get_user_initials(user):
    username = (getattr(user, 'username', '') or '').strip()
    if not username:
        return 'U'

    parts = [part[0].upper() for part in username.replace('_', ' ').split() if part]
    if len(parts) >= 2:
        return ''.join(parts[:2])
    return username[:2].upper()


def get_user_account_snapshot(user):
    profile = get_or_create_user_profile(user)
    websites_qs = Website.objects.filter(user=user)
    incidents_qs = Incident.objects.filter(website__user=user)
    alerts_qs = Alert.objects.filter(website__user=user)

    return {
        'profile': profile,
        'initials': get_user_initials(user),
        'member_since': user.date_joined,
        'last_login': user.last_login,
        'account_status': 'Active' if user.is_active else 'Inactive',
        'monitored_sites_count': websites_qs.count(),
        'resolved_incidents_count': incidents_qs.filter(is_resolved=True).count(),
        'total_incidents_count': incidents_qs.count(),
        'total_alerts_count': alerts_qs.count(),
        'active_alerts_count': alerts_qs.filter(is_read=False).count(),
    }


def account_allows_email_alert(user, alert_type):
    profile = get_or_create_user_profile(user)
    if not profile.email_alerts_enabled:
        return False

    if alert_type == Alert.TYPE_SSL:
        return profile.ssl_alerts_enabled

    if alert_type in {Alert.TYPE_DOWN, Alert.TYPE_SLOW, Alert.TYPE_RECOVERY}:
        return profile.incident_alerts_enabled

    return True


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

    sent_to = (
        website.user.email
        if website.email_notifications
        and website.user.email
        and account_allows_email_alert(website.user, alert_type)
        else ''
    )
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
