import ipaddress
import logging
import re
import socket
import ssl
from email.utils import format_datetime
from datetime import datetime, timedelta, timezone as dt_timezone
from time import perf_counter
from urllib.parse import quote, unquote, urlparse

import requests
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.db import transaction
from django.urls import reverse
from django.utils import timezone

from .emailing import get_email_base_url, get_support_email, render_email_template, send_siteguard_email
from .models import Alert, Incident, IncidentEvent, MonitorLog, Notification, UploadedLog, UserProfile, Website

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
RECENT_SEARCHES_SESSION_KEY = 'siteguard_recent_searches'
ALERT_DEDUP_WINDOW = timedelta(minutes=20)
NOTIFICATION_DEDUP_WINDOW = timedelta(minutes=30)
NOTIFICATION_RETENTION_DAYS = 45
WEEKLY_REPORT_TITLE_RE = re.compile(r"Weekly report ready for (?P<week>\d{4}-W\d{2})")
logger = logging.getLogger(__name__)


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
        existing = latest_logs.get(log.website_id)
        if existing is None or (log.checked_at, log.id or 0) > (existing.checked_at, existing.id or 0):
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


def get_notification_queryset(user):
    return Notification.objects.filter(user=user).select_related(
        'related_incident',
        'related_website',
    )


def get_recent_notifications(user, limit=6):
    if not getattr(user, 'is_authenticated', False):
        return []
    recent_notifications = list(get_notification_queryset(user)[: max(limit * 3, limit)])
    recent_notifications.sort(key=notification_priority, reverse=True)
    return recent_notifications[:limit]


def notification_priority(notification):
    severity_rank = {
        Notification.SEVERITY_CRITICAL: 4,
        Notification.SEVERITY_WARNING: 3,
        Notification.SEVERITY_SUCCESS: 2,
        Notification.SEVERITY_INFO: 1,
    }
    unread_rank = 1 if not notification.is_read else 0
    return (
        unread_rank,
        severity_rank.get(notification.severity, 0),
        notification.created_at,
        notification.id or 0,
    )


def get_unread_notification_count(user):
    if not getattr(user, 'is_authenticated', False):
        return 0
    return Notification.objects.filter(user=user, is_read=False).count()


def create_notification(
    *,
    user,
    title,
    message,
    notification_type,
    severity,
    related_incident=None,
    related_website=None,
):
    recent_cutoff = timezone.now() - NOTIFICATION_DEDUP_WINDOW
    existing = Notification.objects.filter(
        user=user,
        notification_type=notification_type,
        severity=severity,
        related_incident=related_incident,
        related_website=related_website,
        created_at__gte=recent_cutoff,
    ).filter(
        Q(title=title, message=message)
        | Q(is_read=False)
    ).order_by('-created_at', '-id').first()
    if existing:
        return existing

    return Notification.objects.create(
        user=user,
        title=title,
        message=message,
        notification_type=notification_type,
        severity=severity,
        related_incident=related_incident,
        related_website=related_website,
    )


def extract_week_key_from_notification(notification):
    match = WEEKLY_REPORT_TITLE_RE.search(getattr(notification, 'title', '') or '')
    if match:
        return match.group('week')
    return timezone.now().strftime('%G-W%V')


def get_notification_destination(notification):
    if notification.notification_type == Notification.TYPE_REPORT:
        return reverse('weekly_report_detail', args=[extract_week_key_from_notification(notification)])
    if notification.related_incident_id:
        return reverse('incidents')
    if notification.notification_type in {Notification.TYPE_OUTAGE, Notification.TYPE_RECOVERY, Notification.TYPE_SSL, Notification.TYPE_WARNING}:
        return reverse('alerts')
    return reverse('notifications')


def serialize_notification_activity_item(notification):
    return {
        'title': notification.title,
        'message': notification.message,
        'is_read': notification.is_read,
        'created_at': notification.created_at,
        'badge_class': notification.badge_class,
        'severity_label': notification.severity.upper(),
        'icon_bg_class': notification.icon_bg_class,
        'icon_text_class': notification.icon_text_class,
        'icon_name': notification.icon_name,
        'action_url': get_notification_destination(notification),
        'action_label': 'Open Report' if notification.notification_type == Notification.TYPE_REPORT else 'Open',
        'mark_read_url': reverse('mark_notification_read', args=[notification.id]),
        'kind': 'notification',
    }


def build_notification_activity_center(user, limit=8):
    if not getattr(user, 'is_authenticated', False):
        return {
            'summary': {'unread': 0, 'critical': 0, 'reports': 0, 'analyzer_uploads': 0},
            'sections': [],
            'quick_links': [],
        }

    now = timezone.now()
    notifications = list(get_notification_queryset(user)[: max(limit * 4, limit)])
    notifications.sort(key=notification_priority, reverse=True)

    critical_open = [
        notification for notification in notifications
        if (
            not notification.is_read
            and notification.severity in {Notification.SEVERITY_CRITICAL, Notification.SEVERITY_WARNING}
        )
    ]
    recoveries_and_reports = [
        notification for notification in notifications
        if notification.notification_type in {Notification.TYPE_RECOVERY, Notification.TYPE_REPORT}
    ]
    remaining = [
        notification for notification in notifications
        if notification not in critical_open and notification not in recoveries_and_reports
    ]

    recent_uploads = list(
        UploadedLog.objects.filter(
            user=user,
            uploaded_at__gte=now - timedelta(days=7),
        ).prefetch_related('parsed_errors').order_by('-uploaded_at', '-id')[:3]
    )
    analyzer_occurrences = sum(
        parsed_error.count
        for upload in recent_uploads
        for parsed_error in upload.parsed_errors.all()
    )

    sections = []
    if critical_open:
        sections.append({
            'title': 'Critical Signals',
            'subtitle': 'Unread outages and warning states needing review.',
            'items': [serialize_notification_activity_item(item) for item in critical_open[: min(4, limit)]],
        })
    if recoveries_and_reports:
        sections.append({
            'title': 'Recovery + Reports',
            'subtitle': 'Closures, recoveries, and report-ready updates.',
            'items': [serialize_notification_activity_item(item) for item in recoveries_and_reports[:3]],
        })
    if recent_uploads:
        sections.append({
            'title': 'Analyzer Activity',
            'subtitle': 'Recent deterministic analyzer processing.',
            'items': [
                {
                    'title': 'Analyzer workspace updated',
                    'message': f"{len(recent_uploads)} upload{'s' if len(recent_uploads) != 1 else ''} processed with {analyzer_occurrences} grouped occurrence{'s' if analyzer_occurrences != 1 else ''} in the last 7 days.",
                    'is_read': True,
                    'created_at': recent_uploads[0].uploaded_at,
                    'badge_class': 'badge-active',
                    'severity_label': 'ANALYZER',
                    'icon_bg_class': 'bg-active-light',
                    'icon_text_class': 'text-active',
                    'icon_name': 'bug',
                    'action_url': reverse('error_log_upload'),
                    'action_label': 'Open Analyzer',
                    'mark_read_url': '',
                    'kind': 'analyzer',
                }
            ],
        })
    if remaining:
        sections.append({
            'title': 'Recent Activity',
            'subtitle': 'Remaining monitoring and workflow events.',
            'items': [serialize_notification_activity_item(item) for item in remaining[: max(limit - 4, 2)]],
        })

    return {
        'summary': {
            'unread': get_unread_notification_count(user),
            'critical': len(critical_open),
            'reports': sum(1 for notification in notifications if notification.notification_type == Notification.TYPE_REPORT),
            'analyzer_uploads': len(recent_uploads),
        },
        'sections': sections,
        'quick_links': [
            {'label': 'Alerts', 'url': reverse('alerts')},
            {'label': 'Weekly Reports', 'url': reverse('weekly_reports')},
            {'label': 'Analyzer', 'url': reverse('error_log_upload')},
            {'label': 'Notifications', 'url': reverse('notifications')},
        ],
    }


def cleanup_old_notifications(user=None, *, retention_days=NOTIFICATION_RETENTION_DAYS):
    cutoff = timezone.now() - timedelta(days=retention_days)
    queryset = Notification.objects.filter(is_read=True, created_at__lt=cutoff)
    if user is not None:
        queryset = queryset.filter(user=user)
    queryset.delete()


def create_notification_from_alert(alert):
    website = alert.website
    incident = alert.incident
    domain = normalize_domain_display(website.url)

    if alert.alert_type == Alert.TYPE_DOWN:
        title = f"Outage detected for {domain}"
        notification_type = Notification.TYPE_OUTAGE
        severity = Notification.SEVERITY_CRITICAL
    elif alert.alert_type == Alert.TYPE_SLOW:
        title = f"Slow response warning for {domain}"
        notification_type = Notification.TYPE_WARNING
        severity = Notification.SEVERITY_WARNING
    elif alert.alert_type == Alert.TYPE_SSL:
        title = f"SSL warning for {domain}"
        notification_type = Notification.TYPE_SSL
        severity = Notification.SEVERITY_WARNING
    else:
        title = f"Recovery confirmed for {domain}"
        notification_type = Notification.TYPE_RECOVERY
        severity = Notification.SEVERITY_SUCCESS
        if incident and incident.incident_type == Incident.TYPE_SSL:
            title = f"SSL restored for {domain}"

    return create_notification(
        user=website.user,
        title=title,
        message=alert.message,
        notification_type=notification_type,
        severity=severity,
        related_incident=incident,
        related_website=website,
    )


def ensure_weekly_report_notification(user):
    if not getattr(user, 'is_authenticated', False):
        return None

    now = timezone.now()
    week_key = now.strftime('%G-W%V')
    title = f"Weekly report ready for {week_key}"
    message = "Your latest SiteGuard monitoring analytics and uptime trends are ready to review."
    return create_notification(
        user=user,
        title=title,
        message=message,
        notification_type=Notification.TYPE_REPORT,
        severity=Notification.SEVERITY_INFO,
    )


def remember_recent_search(request, query):
    cleaned = (query or '').strip()
    if not cleaned:
        return

    recent = request.session.get(RECENT_SEARCHES_SESSION_KEY, [])
    recent = [item for item in recent if item.lower() != cleaned.lower()]
    recent.insert(0, cleaned)
    request.session[RECENT_SEARCHES_SESSION_KEY] = recent[:5]
    request.session.modified = True


def get_recent_searches(request):
    return request.session.get(RECENT_SEARCHES_SESSION_KEY, [])[:5]


def normalize_search_query(query):
    return (query or '').strip()[:100]


def build_global_search_results(user, query, per_section=6):
    normalized_query = normalize_search_query(query)
    if not getattr(user, 'is_authenticated', False) or not normalized_query:
        return {
            'query': normalized_query,
            'websites': [],
            'incidents': [],
            'alerts': [],
            'notifications': [],
            'logs': [],
            'reports': [],
            'total_count': 0,
        }

    filters = (
        Q(url__icontains=normalized_query)
    )
    websites = list(Website.objects.filter(user=user).filter(filters).order_by('url')[:per_section])
    incidents = list(
        Incident.objects.filter(website__user=user).select_related('website').filter(
            Q(title__icontains=normalized_query) |
            Q(website__url__icontains=normalized_query) |
            Q(status__icontains=normalized_query)
        ).order_by('-started_at')[:per_section]
    )
    alerts = list(
        Alert.objects.filter(website__user=user).select_related('website', 'incident').filter(
            Q(message__icontains=normalized_query) |
            Q(website__url__icontains=normalized_query) |
            Q(alert_type__icontains=normalized_query)
        ).order_by('-created_at')[:per_section]
    )
    notifications = list(
        get_notification_queryset(user).filter(
            Q(title__icontains=normalized_query) |
            Q(message__icontains=normalized_query) |
            Q(notification_type__icontains=normalized_query) |
            Q(related_website__url__icontains=normalized_query)
        )[:per_section]
    )
    logs = list(
        MonitorLog.objects.filter(website__user=user).select_related('website').filter(
            Q(website__url__icontains=normalized_query) |
            Q(status__icontains=normalized_query)
        ).order_by('-checked_at')[:per_section]
    )

    report_matches = []
    if (
        'report' in normalized_query.lower()
        or websites
        or incidents
        or alerts
        or logs
    ):
        report_matches.append({
            'title': 'Open monitoring analytics report',
            'description': f"Analytics for query '{normalized_query}' across your monitored websites.",
            'url_name': 'reports',
        })

    for website in websites:
        website.display_domain = normalize_domain_display(website.url)
    for incident in incidents:
        incident.website.display_domain = normalize_domain_display(incident.website.url)
    for alert in alerts:
        alert.website.display_domain = normalize_domain_display(alert.website.url)
    for log in logs:
        log.display_domain = normalize_domain_display(log.website.url)

    total_count = sum(len(section) for section in (websites, incidents, alerts, notifications, logs, report_matches))
    return {
        'query': normalized_query,
        'websites': websites,
        'incidents': incidents,
        'alerts': alerts,
        'notifications': notifications,
        'logs': logs,
        'reports': report_matches,
        'total_count': total_count,
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


def _format_monitor_timestamp(value):
    if value is None:
        return timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')
    return timezone.localtime(value).strftime('%Y-%m-%d %H:%M:%S %Z')


def _format_email_timestamp(value):
    if value is None:
        value = timezone.now()
    return format_datetime(timezone.localtime(value))


def _format_duration_seconds(total_seconds):
    if total_seconds <= 0:
        return '0m'
    hours, remainder = divmod(int(total_seconds), 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def _infer_operational_cause(detail):
    text = (detail or '').lower()
    if 'dns' in text or 'resolve' in text:
        return 'DNS resolution is preventing the monitor from reaching the host.'
    if 'tls' in text or 'ssl' in text or 'certificate' in text:
        return 'TLS certificate validation or handshake checks are failing.'
    if 'timed out' in text or 'timeout' in text:
        return 'The endpoint is exceeding the monitoring timeout window.'
    if 'connection refused' in text or 'connection could not be established' in text or 'connection to the monitored host failed' in text:
        return 'The origin is refusing or dropping network connections.'
    if 'http 5' in text or 'http status code: 5' in text:
        return 'The application is returning server-side failures during the outage window.'
    if 'response time' in text and 'slow threshold' in text:
        return 'Latency has exceeded the configured slow threshold and indicates degraded performance.'
    return 'Monitoring detected a sustained operational failure that still needs investigation.'


def _get_last_successful_check(website, before_time=None):
    logs = MonitorLog.objects.filter(
        website=website,
        status=MonitorLog.STATUS_UP,
        response_time__gt=0,
    )
    if before_time is not None:
        logs = logs.filter(checked_at__lt=before_time)
    return logs.order_by('-checked_at', '-id').first()


def _get_outage_peak_latency(incident):
    if incident is None:
        return None
    end_time = incident.resolved_at or timezone.now()
    logs = MonitorLog.objects.filter(
        website=incident.website,
        checked_at__gte=incident.started_at,
        checked_at__lte=end_time,
        response_time__isnull=False,
    ).order_by('-response_time')
    peak_log = logs.first()
    if peak_log is None:
        return None
    return peak_log.response_time


def _build_alert_email_context(alert, recovery_time=None):
    incident = alert.incident
    incident_start = incident.started_at if incident else alert.created_at
    last_successful_log = _get_last_successful_check(alert.website, before_time=incident_start)
    outage_duration = None
    if recovery_time is not None and incident_start is not None:
        outage_duration = recovery_time - incident_start
    peak_latency = _get_outage_peak_latency(incident)
    return {
        'probable_cause': _infer_operational_cause(alert.message),
        'last_successful_log': last_successful_log,
        'outage_duration': outage_duration,
        'peak_latency': peak_latency,
    }


def _describe_exception_reason(exc, timeout):
    if isinstance(exc, requests.Timeout):
        return f"Request timed out after {timeout}s."

    if isinstance(exc, requests.ConnectionError):
        detail = str(exc).lower()
        if 'name or service not known' in detail or 'nodename nor servname provided' in detail or 'failed to resolve' in detail:
            return "DNS resolution failed for the monitored host."
        if 'connection refused' in detail:
            return "Connection was actively refused by the target server."
        if 'max retries exceeded' in detail:
            return "Connection could not be established after retry attempts."
        return "Connection to the monitored host failed."

    if isinstance(exc, requests.SSLError):
        return "TLS handshake failed while connecting to the monitored host."

    return f"Monitoring request failed: {exc}"


def build_monitoring_detail(
    *,
    website,
    status,
    checked_at,
    response_time=None,
    threshold=None,
    status_code=None,
    reason='',
    recovery=False,
    previous_status='',
):
    no_response_reason = bool(reason) and any(keyword in reason.lower() for keyword in ('timed out', 'dns', 'connection', 'tls handshake'))
    response_metric = _format_response_time(None if no_response_reason and not response_time else response_time)
    checked_label = _format_monitor_timestamp(checked_at)
    segments = []

    if recovery:
        segments.append(f"{website.url} recovered at {checked_label}.")
        if previous_status:
            segments.append(f"Previous state: {previous_status}.")
        if status_code is not None:
            segments.append(f"HTTP status {status_code} is now returning successfully.")
        if response_time is not None:
            segments.append(f"Current response metric: {response_metric}.")
        if threshold is not None and response_time is not None:
            segments.append(f"This is below the slow threshold of {threshold}ms.")
        if reason:
            segments.append(f"Recovery context: {reason}.")
        return ' '.join(segments)

    if status == MonitorLog.STATUS_DOWN:
        segments.append(f"Automated monitoring detected {website.url} as DOWN at {checked_label}.")
        if reason:
            segments.append(f"Reason: {reason}")
        if status_code is not None:
            segments.append(f"HTTP status code: {status_code}.")
        segments.append(f"Response metric: {response_metric}.")
        return ' '.join(segments)

    if status == MonitorLog.STATUS_SLOW:
        segments.append(f"Automated monitoring detected degraded performance for {website.url} at {checked_label}.")
        if response_time is not None and threshold is not None:
            segments.append(f"Response time {response_metric} exceeded the slow threshold of {threshold}ms.")
        elif response_time is not None:
            segments.append(f"Measured response time: {response_metric}.")
        if status_code is not None:
            segments.append(f"HTTP status code: {status_code}.")
        if reason:
            segments.append(f"Reason: {reason}")
        return ' '.join(segments)

    segments.append(f"SSL validation failed for {website.url} at {checked_label}.")
    if reason:
        segments.append(f"Reason: {reason}")
    if status_code is not None:
        segments.append(f"Latest HTTP status code: {status_code}.")
    segments.append(f"Response metric: {response_metric}.")
    return ' '.join(segments)


def build_recovery_context(previous_status, response_time, threshold, status_code):
    if previous_status == MonitorLog.STATUS_DOWN:
        return "The monitored endpoint is reachable again."
    if previous_status == MonitorLog.STATUS_SLOW:
        if response_time is not None and threshold is not None:
            return f"Response time returned below the configured slow threshold of {threshold}ms."
        return "Performance returned to the normal operating range."
    if status_code is not None:
        return f"Latest check returned HTTP {status_code} with a healthy response."
    return "Monitoring recovered to a healthy state."


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


def _build_canonical_url(path):
    base_url = get_email_base_url()
    normalized_path = f"/{(path or '').lstrip('/')}"
    if base_url:
        return f"{base_url}{normalized_path}"
    return normalized_path


def _get_alert_subject(alert):
    website_label = normalize_domain_display(alert.website.url) or alert.website.url
    if alert.alert_type == Alert.TYPE_DOWN:
        return f"Operational alert: {website_label} is down"
    if alert.alert_type == Alert.TYPE_SLOW:
        return f"Operational warning: {website_label} latency is degraded"
    if alert.alert_type == Alert.TYPE_RECOVERY:
        return f"Recovery notice: {website_label} is operational again"
    return f"SSL warning: {website_label} certificate validation failed"


def _build_alert_email_bodies(alert, *, recovery_time=None):
    website = alert.website
    incident = alert.incident
    incident_start = incident.started_at if incident else alert.created_at
    response_time = _format_response_time(alert.response_time)
    email_context = _build_alert_email_context(alert, recovery_time=recovery_time)
    dashboard_url = _build_canonical_url(reverse("alerts"))
    incident_url = _build_canonical_url(reverse("incidents"))

    text_lines = [
        f"{getattr(settings, 'SITE_NAME', 'SiteGuard')} Monitoring Alert",
        "",
        f"Website: {website.url}",
        f"Alert Type: {alert.alert_type}",
        f"Delivery Status: {alert.status}",
        f"Response Metric: {response_time}",
        f"Incident Started: {_format_email_timestamp(incident_start)}",
        f"Alert Generated: {_format_email_timestamp(alert.created_at)}",
        f"Alerts Dashboard: {dashboard_url}",
    ]
    if incident is not None:
        text_lines.append(f"Incident Timeline: {incident_url}")
    if email_context['last_successful_log'] is not None:
        text_lines.append(f"Last Successful Check: {_format_email_timestamp(email_context['last_successful_log'].checked_at)}")
    text_lines.append(f"Operational Assessment: {email_context['probable_cause']}")
    if recovery_time is not None:
        text_lines.append(f"Recovery Time: {_format_email_timestamp(recovery_time)}")
        if email_context['outage_duration'] is not None:
            text_lines.append(f"Downtime Duration: {_format_duration_seconds(email_context['outage_duration'].total_seconds())}")
    if incident is not None:
        text_lines.append(f"Incident Reference: {incident.incident_code}")
        text_lines.append(f"Incident Category: {incident.get_incident_type_display()}")
        if incident.status == Incident.STATUS_RESOLVED:
            text_lines.append("Current Outage State: Recovered and monitoring stabilized.")
        else:
            text_lines.append(f"Current Outage State: {incident.status}")
        if incident.latest_response_time is not None:
            text_lines.append(f"Latest Incident Latency: {_format_response_time(incident.latest_response_time)}")
    if email_context['peak_latency'] is not None:
        text_lines.append(f"Peak Latency During Window: {_format_response_time(email_context['peak_latency'])}")
    if alert.sent_to:
        text_lines.append(f"Recipient: {alert.sent_to}")

    detail_notes = []
    lowered_message = alert.message.lower()
    if 'timed out' in lowered_message or 'timeout' in lowered_message:
        detail_notes.append('Timeout indicator: monitor requests exceeded the configured timeout window.')
    if 'tls' in lowered_message or 'ssl' in lowered_message or 'certificate' in lowered_message:
        detail_notes.append('SSL indicator: certificate validation or TLS handshake checks reported a failure.')
    if 'dns' in lowered_message or 'resolve' in lowered_message:
        detail_notes.append('DNS indicator: host resolution failed before the request could complete.')
    if 'connection refused' in lowered_message or 'connection to the monitored host failed' in lowered_message:
        detail_notes.append('Connection indicator: the origin refused or failed to accept network connections.')
    if 'response time' in lowered_message and 'slow threshold' in lowered_message:
        detail_notes.append('Escalation context: latency crossed the configured slow threshold and triggered degraded-state handling.')

    text_lines.extend([
        "",
        "Alert Details:",
        alert.message,
    ])
    if detail_notes:
        text_lines.extend([
            "",
            "Operational Hints:",
            *detail_notes,
        ])

    if alert.alert_type == Alert.TYPE_RECOVERY:
        text_lines.extend([
            "",
            "Recovery Summary:",
            "Recovery confirmation: the monitor returned a healthy result and closed the active outage window.",
            f"Operational recovery status: {'Recovered' if incident and incident.is_resolved else 'Healthy check confirmed'}.",
        ])

    html_body = render_email_template(
        "monitor/emails/alert_email.html",
        {
            "site_name": getattr(settings, "SITE_NAME", "SiteGuard"),
            "support_email": get_support_email(),
            "subject": _get_alert_subject(alert),
            "website": website,
            "alert": alert,
            "incident": incident,
            "incident_start": incident_start,
            "response_time": response_time,
            "email_context": email_context,
            "recovery_time": recovery_time,
            "dashboard_url": dashboard_url,
            "incident_url": incident_url,
            "detail_notes": detail_notes,
        },
    )
    return "\n".join(text_lines), html_body


def send_alert_email(alert, recovery_time=None):
    subject = _get_alert_subject(alert)
    text_body, html_body = _build_alert_email_bodies(alert, recovery_time=recovery_time)
    return send_siteguard_email(
        subject=subject,
        text_body=text_body,
        html_body=html_body,
        recipients=[alert.website.user.email],
        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', None),
        log_context={
            "flow": "operational_alert",
            "alert_id": alert.id,
            "alert_type": alert.alert_type,
            "website_id": alert.website_id,
            "incident_id": alert.incident_id,
        },
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
    recent_cutoff = timezone.now() - ALERT_DEDUP_WINDOW
    active_alert_filters = {
        'website': website,
        'alert_type': alert_type,
    }
    if incident is not None:
        active_alert_filters['incident'] = incident
    else:
        active_alert_filters['created_at__gte'] = recent_cutoff

    alert = Alert.objects.filter(**active_alert_filters).order_by('-created_at', '-id').first()
    reused_existing_alert = alert is not None

    if (
        alert
        and alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING}
        and alert.message == message
    ):
        if response_time is not None and alert.response_time != response_time:
            alert.response_time = response_time
            alert.save(update_fields=['response_time'])
        create_notification_from_alert(alert)
        return alert

    if alert and alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING, Alert.STATUS_FAILED}:
        alert.message = message
        alert.sent_to = sent_to
        alert.response_time = get_numeric_response_time(response_time, default=None)
        update_fields = ['message', 'sent_to', 'response_time']
        if alert.status == Alert.STATUS_FAILED and not sent_to:
            alert.status = Alert.STATUS_SENT
            update_fields.append('status')
        alert.save(update_fields=update_fields)
    else:
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
        create_notification_from_alert(alert)
        return alert

    if reused_existing_alert and alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING}:
        create_notification_from_alert(alert)
        return alert

    sent = send_alert_email(alert, recovery_time=recovery_time)
    if sent:
        alert.status = Alert.STATUS_SENT
        alert.sent_to = sent_to
        alert.save(update_fields=['status', 'sent_to'])
    else:
        alert.status = Alert.STATUS_FAILED
        alert.save(update_fields=['status'])
        logger.warning(
            "Operational alert email delivery failed.",
            extra={
                "email_context": {
                    "flow": "operational_alert",
                    "alert_id": alert.id,
                    "alert_type": alert.alert_type,
                    "website_id": website.id,
                }
            },
        )

    create_notification_from_alert(alert)
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
                and (alert_key + (alert.message, alert.sent_to)) in alert_seen
            ):
                alert.is_read = True
                alert.read_at = alert.read_at or alert.created_at
                update_fields.extend(['is_read', 'read_at'])
            else:
                alert_seen.add(alert_key + (alert.message, alert.sent_to))

            if update_fields:
                alert.save(update_fields=update_fields)


def resolve_incident(incident, current_log, create_recovery_alert=False, message=None, status_code=None):
    previous_status = incident.status
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
        message or build_monitoring_detail(
            website=incident.website,
            status=MonitorLog.STATUS_UP,
            checked_at=current_log.checked_at,
            response_time=current_log.response_time,
            threshold=get_monitor_threshold(incident.website),
            status_code=status_code,
            previous_status=previous_status,
            reason=build_recovery_context(previous_status, current_log.response_time, get_monitor_threshold(incident.website), status_code),
            recovery=True,
        ),
    )

    if create_recovery_alert:
        create_or_update_alert(
            incident.website,
            Alert.TYPE_RECOVERY,
            build_monitoring_detail(
                website=incident.website,
                status=MonitorLog.STATUS_UP,
                checked_at=current_log.checked_at,
                response_time=current_log.response_time,
                threshold=get_monitor_threshold(incident.website),
                status_code=status_code,
                previous_status=previous_status,
                reason=build_recovery_context(previous_status, current_log.response_time, get_monitor_threshold(incident.website), status_code),
                recovery=True,
            ),
            incident=incident,
            response_time=current_log.response_time,
            recovery_time=current_log.checked_at,
        )


def sync_incident_state(website, previous_log, current_log, *, status_code=None, reason=''):
    previous_status = get_site_status(previous_log)
    current_status = get_site_status(current_log)
    active_incidents = Incident.objects.filter(
        website=website,
        is_resolved=False,
    ).exclude(incident_type=Incident.TYPE_SSL).order_by('-started_at')

    if current_status == MonitorLog.STATUS_UP:
        for incident in active_incidents:
            resolve_incident(incident, current_log, create_recovery_alert=True, status_code=status_code)
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
            status_code=status_code,
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
        detail = build_monitoring_detail(
            website=website,
            status=current_status,
            checked_at=current_log.checked_at,
            response_time=current_log.response_time,
            threshold=get_monitor_threshold(website),
            status_code=status_code,
            reason=reason,
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
            build_monitoring_detail(
                website=website,
                status=current_status,
                checked_at=current_log.checked_at,
                response_time=current_log.response_time,
                threshold=get_monitor_threshold(website),
                status_code=status_code,
                reason=f"{reason} Previous state was {previous_status}." if reason else f"Previous state was {previous_status}.",
            ),
        )


def sync_ssl_state(website, current_log, ssl_status, *, status_code=None, reason=''):
    if ssl_status not in {"Valid", "Invalid"}:
        return

    if ssl_status == "Invalid":
        active_non_ssl_incidents = Incident.objects.filter(
            website=website,
            is_resolved=False,
        ).exclude(incident_type=Incident.TYPE_SSL).order_by('-started_at')
        for incident in active_non_ssl_incidents:
            resolve_incident(
                incident,
                current_log,
                create_recovery_alert=False,
                message="Non-SSL incident automatically closed because TLS validation failure is the active condition.",
                status_code=status_code,
            )

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
                message=build_monitoring_detail(
                    website=website,
                    status=MonitorLog.STATUS_UP,
                    checked_at=current_log.checked_at,
                    response_time=current_log.response_time,
                    threshold=get_monitor_threshold(website),
                    status_code=status_code,
                    previous_status=MonitorLog.STATUS_SLOW,
                    reason="TLS certificate checks are passing again.",
                    recovery=True,
                ),
                status_code=status_code,
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
            build_monitoring_detail(
                website=website,
                status='SSL',
                checked_at=current_log.checked_at,
                response_time=current_log.response_time,
                status_code=status_code,
                reason=reason or "TLS handshake or certificate validation failed during monitoring.",
            ),
        )
        create_or_update_alert(
            website,
            Alert.TYPE_SSL,
            build_monitoring_detail(
                website=website,
                status='SSL',
                checked_at=current_log.checked_at,
                response_time=current_log.response_time,
                status_code=status_code,
                reason=reason or "TLS handshake or certificate validation failed during monitoring.",
            ),
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

    previous_log = MonitorLog.objects.filter(website=website).order_by('-checked_at', '-id').first()
    ssl_status = None
    status_code = None
    reason = ''
    ssl_reason = ''

    try:
        response = requests.get(url, timeout=timeout)
        response_time_ms = response.elapsed.total_seconds() * 1000
        status_code = response.status_code
        ssl_status = check_ssl_status(url)

        if 200 <= response.status_code < 400:
            status = (
                MonitorLog.STATUS_SLOW
                if response_time_ms > 2000
                else MonitorLog.STATUS_UP
            )
            if status == MonitorLog.STATUS_SLOW:
                reason = f"Response time {_format_response_time(response_time_ms)} exceeded the configured slow threshold of {get_monitor_threshold(website)}ms."
        else:
            status = MonitorLog.STATUS_DOWN
            reason = f"HTTP {response.status_code} returned by the monitored endpoint."

        if ssl_status == "Invalid":
            ssl_reason = "TLS handshake or certificate validation failed during certificate checks."

        log = MonitorLog.objects.create(
            website=website,
            status=status,
            response_time=round(response_time_ms, 2),
        )
        sync_incident_state(website, previous_log, log, status_code=status_code, reason=reason)
        sync_ssl_state(website, log, ssl_status, status_code=status_code, reason=ssl_reason)
        return log, response
    except Exception as exc:
        reason = _describe_exception_reason(exc, timeout)
        if isinstance(exc, requests.exceptions.SSLError):
            ssl_status = "Invalid"
            ssl_reason = "TLS handshake or certificate validation failed during the monitoring request."
        log = MonitorLog.objects.create(
            website=website,
            status=MonitorLog.STATUS_DOWN,
            response_time=0,
        )
        if ssl_status != "Invalid":
            sync_incident_state(website, previous_log, log, status_code=status_code, reason=reason)
        sync_ssl_state(website, log, ssl_status, status_code=status_code, reason=ssl_reason)
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
