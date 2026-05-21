import logging
import math
import os
import re
import subprocess
from datetime import datetime, timedelta
from collections import Counter, defaultdict
from functools import lru_cache
from hmac import compare_digest
from io import StringIO

from django.conf import settings as django_settings
from django.contrib.auth import views as auth_views
from django.shortcuts import get_object_or_404, redirect, render
from django.http import Http404, HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.management import call_command
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError
from django.db.models import Avg, Count, Q, Sum
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
from django.utils import timezone

from .emailing import get_email_diagnostics
from .forms import (
    AccountPasswordChangeForm,
    AccountPreferencesForm,
    AccountSecurityForm,
    DeleteAccountForm,
    LoginForm,
    ProfileUpdateForm,
    SiteGuardPasswordResetForm,
    SignUpForm,
    UploadedLogForm,
)
from .error_analyzer import build_upload_analytics, get_error_diagnostics, iter_error_entries, process_uploaded_log
from .models import Alert, Incident, MonitorLog, ParsedError, UploadedLog, Website
from .ai.services.analysis import (
    generate_error_upload_analysis,
    generate_incident_analysis,
    generate_report_analysis,
    get_error_upload_ai_state,
    get_incident_ai_state,
    get_report_ai_state,
)
from .utils import (
    ALERT_DEDUP_WINDOW,
    analyze_domain,
    build_global_search_results,
    check_ssl_status,
    cleanup_old_notifications,
    cleanup_monitoring_state,
    ensure_weekly_report_notification,
    get_notification_destination,
    get_favicon_url,
    get_latest_logs_by_website,
    get_notification_queryset,
    notification_priority,
    get_or_create_user_profile,
    get_recent_searches,
    get_user_account_snapshot,
    get_unread_notification_count,
    remember_recent_search,
    normalize_domain_display,
    normalize_utility_domain,
    send_alert_email,
    safe_url_decode,
    safe_url_encode,
    get_valid_response_times,
    get_site_snapshot,
    get_site_status,
    run_single_check,
)

logger = logging.getLogger(__name__)
password_reset_logger = logging.getLogger("siteguard.email")

TIMESTAMP_RE = re.compile(
    r'(?P<stamp>('
    r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(?::\d{2})?'
    r'|\d{2}:\d{2}(?::\d{2})?'
    r'))'
)
ROUTE_RE = re.compile(r'(?P<route>/(?:[\w\-./{}:%]+)?)')
SERVICE_RE = re.compile(r'(?i)\b(?:service|worker|queue|api|db|redis|postgres|mysql|nginx|gunicorn|celery)\b')
CONFIDENCE_COPY = {
    'high': 'High confidence',
    'medium': 'Medium confidence',
    'low': 'Low confidence',
}


class SiteGuardPasswordResetView(auth_views.PasswordResetView):
    form_class = SiteGuardPasswordResetForm
    template_name = "registration/password_reset_form.html"
    email_template_name = "registration/password_reset_email.txt"
    subject_template_name = "registration/password_reset_subject.txt"

    def form_valid(self, form):
        password_reset_logger.info(
            "Password reset view received a valid form submission.",
            extra={
                "email_context": {
                    "flow": "password_reset",
                    "stage": "view_form_valid",
                    "view_class": self.__class__.__name__,
                    "form_class": form.__class__.__name__,
                    "submitted_email": form.cleaned_data.get("email", ""),
                    "path": self.request.path,
                }
            },
        )
        return super().form_valid(form)

    def form_invalid(self, form):
        password_reset_logger.warning(
            "Password reset view rejected an invalid form submission.",
            extra={
                "email_context": {
                    "flow": "password_reset",
                    "stage": "view_form_invalid",
                    "view_class": self.__class__.__name__,
                    "form_class": form.__class__.__name__,
                    "submitted_email": form.data.get("email", ""),
                    "errors": form.errors.get_json_data(),
                    "path": self.request.path,
                }
            },
        )
        return super().form_invalid(form)


def _auth_user_table_ready():
    try:
        return User._meta.db_table in connection.introspection.table_names()
    except (OperationalError, ProgrammingError):
        logger.warning("Auth tables are not ready yet; skipping admin bootstrap.", exc_info=True)
        return False


def format_duration_value(total_seconds):
    if total_seconds <= 0:
        return "0m"

    hours, remainder = divmod(int(total_seconds), 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def get_range_start(range_key):
    now = timezone.now()
    if range_key == '24h':
        return now - timedelta(hours=24)
    if range_key == '30d':
        return now - timedelta(days=30)
    return now - timedelta(days=7)


def get_log_message(log):
    status = get_site_status(log)
    if status == "DOWN":
        return "Connection failed"
    if status == "SLOW":
        return "Response exceeded threshold"
    return "Website reachable"


def set_display_domain(obj, url_attr='url', display_attr='display_domain'):
    setattr(obj, display_attr, normalize_domain_display(getattr(obj, url_attr, '')))
    return obj


def serialize_log(log):
    status = get_site_status(log)
    response_time = round(log.response_time, 2) if log.response_time is not None else 0
    return {
        'website': log.website,
        'url': log.website.url,
        'display_domain': normalize_domain_display(log.website.url),
        'status': status,
        'response_time': response_time,
        'response_time_display': f"{response_time:g} ms" if log.response_time is not None else '—',
        'checked_at': log.checked_at,
        'message': get_log_message(log),
        'badge_class': (
            'badge-down' if status == 'DOWN'
            else 'badge-slow' if status == 'SLOW'
            else 'badge-up'
        ),
    }


def build_time_series(logs, range_key):
    now = timezone.now()
    if range_key == '24h':
        labels = [
            (now - timedelta(hours=hour_offset)).replace(minute=0, second=0, microsecond=0)
            for hour_offset in range(23, -1, -2)
        ]
        bucket_key = lambda dt: dt.replace(minute=0, second=0, microsecond=0)
        label_format = lambda dt: dt.strftime('%H:%M')
        bucket_step = 2
    else:
        days = 30 if range_key == '30d' else 7
        start_day = (now - timedelta(days=days - 1)).date()
        labels = [start_day + timedelta(days=index) for index in range(days)]
        bucket_key = lambda dt: dt.date()
        label_format = lambda dt: dt.strftime('%b %d')
        bucket_step = 1

    uptime_counts = {label: {'up': 0, 'total': 0} for label in labels}
    response_totals = {label: {'total': 0.0, 'count': 0} for label in labels}
    error_counts = {label: 0 for label in labels}
    percentile_values = {label: [] for label in labels}

    for log in logs:
        key = bucket_key(log.checked_at)
        if key not in uptime_counts:
            if range_key == '24h':
                aligned_hour = key.hour - (key.hour % bucket_step)
                key = key.replace(hour=aligned_hour, minute=0, second=0, microsecond=0)
        if key not in uptime_counts:
            continue

        status = get_site_status(log)
        uptime_counts[key]['total'] += 1
        if status == "UP":
            uptime_counts[key]['up'] += 1
        else:
            error_counts[key] += 1

        if log.response_time is not None:
            response_totals[key]['total'] += float(log.response_time)
            response_totals[key]['count'] += 1
            percentile_values[key].append(float(log.response_time))

    chart_labels = [label_format(label) for label in labels]
    uptime_trend = [
        round((uptime_counts[label]['up'] / uptime_counts[label]['total']) * 100, 2)
        if uptime_counts[label]['total'] else 0
        for label in labels
    ]
    response_trend = [
        round(response_totals[label]['total'] / response_totals[label]['count'], 2)
        if response_totals[label]['count'] else 0
        for label in labels
    ]
    error_trend = [error_counts[label] for label in labels]

    percentile_p50 = []
    percentile_p95 = []
    percentile_p99 = []
    for label in labels:
        values = sorted(percentile_values[label])
        if not values:
            percentile_p50.append(0)
            percentile_p95.append(0)
            percentile_p99.append(0)
            continue

        def percentile(percent):
            index = max(int((len(values) - 1) * percent), 0)
            return round(values[index], 2)

        percentile_p50.append(percentile(0.50))
        percentile_p95.append(percentile(0.95))
        percentile_p99.append(percentile(0.99))

    return {
        'labels': chart_labels,
        'uptime_trend': uptime_trend,
        'response_trend': response_trend,
        'error_trend': error_trend,
        'percentile_p50': percentile_p50,
        'percentile_p95': percentile_p95,
        'percentile_p99': percentile_p99,
    }


def build_heatmap_rows(websites, logs):
    hour_labels = [f"{hour:02d}:00" for hour in range(0, 24, 2)]
    grouped = defaultdict(lambda: defaultdict(list))

    for log in logs:
        bucket = log.checked_at.hour - (log.checked_at.hour % 2)
        grouped[log.website_id][bucket].append(log)

    rows = []
    for website in websites:
        set_display_domain(website)
        cells = []
        for hour in range(0, 24, 2):
            bucket_logs = grouped[website.id].get(hour, [])
            if not bucket_logs:
                cells.append({'class': 'bg-ok', 'label': 'No data'})
                continue

            statuses = [get_site_status(log) for log in bucket_logs]
            valid_times = [
                float(log.response_time)
                for log in bucket_logs
                if log.response_time is not None
            ]
            avg_time = round(sum(valid_times) / len(valid_times), 2) if valid_times else 0

            if "DOWN" in statuses:
                block_class = 'bg-critical'
                block_label = 'DOWN'
            elif avg_time > 2000:
                block_class = 'bg-warn'
                block_label = 'SLOW'
            elif avg_time > 800:
                block_class = 'bg-ok'
                block_label = 'NORMAL'
            else:
                block_class = 'bg-good'
                block_label = 'FAST'

            cells.append({
                'class': block_class,
                'label': f"{block_label} ({avg_time}ms)" if avg_time else block_label,
            })

        rows.append({
            'website': website,
            'display_domain': website.display_domain,
            'cells': cells,
        })

    return hour_labels, rows


def build_reports_context(user, range_key):
    cleanup_monitoring_state(user=user)
    range_start = get_range_start(range_key)
    now = timezone.now()
    websites = list(Website.objects.filter(user=user).order_by('-created_at'))
    for website in websites:
        set_display_domain(website)
    website_ids = [website.id for website in websites]

    logs_qs = MonitorLog.objects.filter(
        website__user=user,
        checked_at__gte=range_start,
    ).select_related('website').order_by('-checked_at')
    logs = list(logs_qs)

    incidents_qs = Incident.objects.filter(
        website__user=user,
        started_at__gte=range_start,
    ).select_related('website').order_by('-started_at')
    alerts_qs = Alert.objects.filter(
        website__user=user,
        created_at__gte=range_start,
    ).select_related('website', 'incident').order_by('-created_at')

    issue_logs_today = [
        log for log in logs
        if log.checked_at >= now - timedelta(hours=24) and get_site_status(log) in {"DOWN", "SLOW"}
    ]
    valid_response_times = [
        float(log.response_time)
        for log in logs
        if log.response_time is not None
    ]
    up_count = sum(1 for log in logs if get_site_status(log) == "UP")
    average_uptime = round((up_count / len(logs)) * 100, 2) if logs else 0
    average_response_time = round(sum(valid_response_times) / len(valid_response_times), 2) if valid_response_times else 0

    website_metrics = defaultdict(lambda: {'total': 0.0, 'count': 0})
    for log in logs:
        if log.response_time is not None:
            website_metrics[log.website_id]['total'] += float(log.response_time)
            website_metrics[log.website_id]['count'] += 1

    slowest_websites = []
    for website in websites:
        metrics = website_metrics.get(website.id)
        if not metrics or not metrics['count']:
            continue
        slowest_websites.append({
            'website': website,
            'display_domain': website.display_domain,
            'average_response_time': round(metrics['total'] / metrics['count'], 2),
        })
    slowest_websites.sort(key=lambda item: item['average_response_time'], reverse=True)
    slowest_websites = slowest_websites[:5]

    most_incidents = [
        {
            'website__url': item['website__url'],
            'display_domain': normalize_domain_display(item['website__url']),
            'total': item['total'],
        }
        for item in Incident.objects.filter(
            website__user=user,
            started_at__gte=range_start,
        ).values('website__url').annotate(total=Count('id')).order_by('-total', 'website__url')[:5]
    ]

    recent_outages = list(
        Incident.objects.filter(
            website__user=user,
            incident_type=Incident.TYPE_OUTAGE,
            started_at__gte=range_start,
        ).select_related('website').order_by('-started_at')[:5]
    )
    for incident in recent_outages:
        set_display_domain(incident.website)
    ssl_failures = incidents_qs.filter(incident_type=Incident.TYPE_SSL).count()

    alert_counts = {
        'active': alerts_qs.filter(is_read=False).exclude(alert_type=Alert.TYPE_RECOVERY).exclude(status=Alert.STATUS_FAILED).count(),
        'recovery': alerts_qs.filter(alert_type=Alert.TYPE_RECOVERY).count(),
        'failed': alerts_qs.filter(status=Alert.STATUS_FAILED).count(),
    }

    chart_data = build_time_series(logs, range_key)
    heatmap_labels, heatmap_rows = build_heatmap_rows(websites, logs)

    distribution_rows = [
        {
            'label': 'Slow Checks',
            'count': sum(1 for log in logs if get_site_status(log) == "SLOW"),
            'class': 'bg-warning',
        },
        {
            'label': 'Down Checks',
            'count': sum(1 for log in logs if get_site_status(log) == "DOWN"),
            'class': 'bg-danger',
        },
        {
            'label': 'SSL Failures',
            'count': ssl_failures,
            'class': 'bg-active',
        },
        {
            'label': 'Failed Alerts',
            'count': alert_counts['failed'],
            'class': 'bg-danger',
        },
    ]
    distribution_total = sum(row['count'] for row in distribution_rows)
    for row in distribution_rows:
        row['percentage'] = round((row['count'] / distribution_total) * 100) if distribution_total else 0

    export_rows = [
        {
            'date': log.checked_at.strftime('%Y-%m-%d %H:%M'),
            'website': log.website.url,
            'status': get_site_status(log),
            'response_time': round(log.response_time, 2) if log.response_time is not None else '',
        }
        for log in logs[:100]
    ]

    error_analytics = build_error_report_analytics(user, range_start, range_key)

    return {
        'selected_range': range_key,
        'range_start': range_start,
        'websites': websites,
        'logs_count': len(logs),
        'total_issues_today': len(issue_logs_today),
        'average_uptime': average_uptime,
        'average_response_time': average_response_time,
        'slowest_websites': slowest_websites,
        'most_incidents': most_incidents,
        'recent_outages': recent_outages,
        'ssl_failures': ssl_failures,
        'alert_counts': alert_counts,
        'chart_data': chart_data,
        'heatmap_labels': heatmap_labels,
        'heatmap_rows': heatmap_rows,
        'distribution_rows': distribution_rows,
        'export_rows': export_rows,
        'has_monitoring_data': bool(logs),
        'error_analytics': error_analytics,
    }


def get_week_window(week_key=None):
    now = timezone.localtime(timezone.now())
    if week_key:
        try:
            week_start = datetime.strptime(f"{week_key}-1", "%G-W%V-%u")
            week_start = timezone.make_aware(week_start, timezone.get_current_timezone())
        except ValueError:
            week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        week_start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    week_end = week_start + timedelta(days=7)
    return week_start, week_end


def _build_weekly_trend(logs, week_start):
    labels = []
    uptime_trend = []
    response_trend = []
    outage_trend = []
    for day_offset in range(7):
        day_start = week_start + timedelta(days=day_offset)
        day_end = day_start + timedelta(days=1)
        day_logs = [log for log in logs if day_start <= log.checked_at < day_end]
        valid_times = [float(log.response_time) for log in day_logs if log.response_time is not None]
        labels.append(day_start.strftime('%a'))
        if day_logs:
            up_count = sum(1 for log in day_logs if get_site_status(log) == "UP")
            uptime_trend.append(round((up_count / len(day_logs)) * 100, 2))
        else:
            uptime_trend.append(0)
        response_trend.append(round(sum(valid_times) / len(valid_times), 2) if valid_times else 0)
        outage_trend.append(sum(1 for log in day_logs if get_site_status(log) == "DOWN"))
    return {
        'labels': labels,
        'uptime_trend': uptime_trend,
        'response_trend': response_trend,
        'outage_trend': outage_trend,
    }


def build_weekly_report_context(user, week_key=None):
    cleanup_monitoring_state(user=user)
    week_start, week_end = get_week_window(week_key)
    previous_week_start = week_start - timedelta(days=7)
    previous_week_end = week_start
    resolved_week_key = week_start.strftime('%G-W%V')

    websites = list(Website.objects.filter(user=user).order_by('url'))
    for website in websites:
        set_display_domain(website)

    logs = list(
        MonitorLog.objects.filter(
            website__user=user,
            checked_at__gte=week_start,
            checked_at__lt=week_end,
        ).select_related('website').order_by('-checked_at')
    )
    previous_logs = list(
        MonitorLog.objects.filter(
            website__user=user,
            checked_at__gte=previous_week_start,
            checked_at__lt=previous_week_end,
        ).select_related('website')
    )
    incidents = list(
        Incident.objects.filter(
            website__user=user,
            started_at__gte=week_start,
            started_at__lt=week_end,
        ).select_related('website').order_by('-started_at', '-created_at')
    )
    alerts = list(
        Alert.objects.filter(
            website__user=user,
            created_at__gte=week_start,
            created_at__lt=week_end,
        ).select_related('website', 'incident').order_by('-created_at', '-id')
    )
    uploads = list(
        UploadedLog.objects.filter(
            user=user,
            uploaded_at__gte=week_start,
            uploaded_at__lt=week_end,
        ).prefetch_related('parsed_errors').order_by('-uploaded_at', '-id')
    )
    notifications = list(
        get_notification_queryset(user).filter(
            created_at__gte=week_start,
            created_at__lt=week_end,
        ).order_by('-created_at', '-id')[:20]
    )

    valid_response_times = [float(log.response_time) for log in logs if log.response_time is not None]
    up_count = sum(1 for log in logs if get_site_status(log) == "UP")
    average_uptime = round((up_count / len(logs)) * 100, 2) if logs else 0
    previous_valid_times = [float(log.response_time) for log in previous_logs if log.response_time is not None]
    previous_up_count = sum(1 for log in previous_logs if get_site_status(log) == "UP")
    previous_average_uptime = round((previous_up_count / len(previous_logs)) * 100, 2) if previous_logs else 0
    average_response_time = round(sum(valid_response_times) / len(valid_response_times), 2) if valid_response_times else 0
    previous_average_response_time = round(sum(previous_valid_times) / len(previous_valid_times), 2) if previous_valid_times else 0

    downtime_logs = [log for log in logs if get_site_status(log) == "DOWN"]
    assumed_check_interval_seconds = 300
    downtime_duration_seconds = len(downtime_logs) * assumed_check_interval_seconds
    outage_frequency = len([incident for incident in incidents if incident.incident_type == Incident.TYPE_OUTAGE])
    recovery_count = len([alert for alert in alerts if alert.alert_type == Alert.TYPE_RECOVERY])
    alert_count = len(alerts)
    incident_count = len(incidents)

    instability_by_site = defaultdict(lambda: {'issues': 0, 'total_response': 0.0, 'responses': 0, 'website': None})
    for log in logs:
        bucket = instability_by_site[log.website_id]
        bucket['website'] = log.website
        if get_site_status(log) != "UP":
            bucket['issues'] += 1
        if log.response_time is not None:
            bucket['total_response'] += float(log.response_time)
            bucket['responses'] += 1

    most_unstable_site = None
    slowest_site = None
    if instability_by_site:
        most_unstable_site = max(instability_by_site.values(), key=lambda item: item['issues'])
        slowest_candidates = [item for item in instability_by_site.values() if item['responses']]
        if slowest_candidates:
            slowest_site = max(slowest_candidates, key=lambda item: item['total_response'] / item['responses'])
    if most_unstable_site and most_unstable_site['website']:
        set_display_domain(most_unstable_site['website'])
    if slowest_site and slowest_site['website']:
        set_display_domain(slowest_site['website'])
    if slowest_site and slowest_site['responses']:
        slowest_site['average_response_time'] = round(slowest_site['total_response'] / slowest_site['responses'], 2)

    parsed_errors = [parsed_error for upload in uploads for parsed_error in upload.parsed_errors.all()]
    analyzer_occurrences = sum(parsed_error.count for parsed_error in parsed_errors)
    severity_counter = Counter()
    for parsed_error in parsed_errors:
        severity_counter[parsed_error.severity] += parsed_error.count
    severity_breakdown = [
        {'label': dict(ParsedError.SEVERITY_CHOICES).get(key, key.title()), 'count': severity_counter.get(key, 0), 'badge_class': badge}
        for key, badge in (
            (ParsedError.SEVERITY_CRITICAL, 'badge-down'),
            (ParsedError.SEVERITY_HIGH, 'badge-slow'),
            (ParsedError.SEVERITY_MEDIUM, 'badge-purple'),
            (ParsedError.SEVERITY_LOW, 'badge-info'),
        )
        if severity_counter.get(key, 0)
    ]

    health_overview = []
    health_overview.append({
        'title': 'Coverage',
        'value': f"{len(websites)} monitored site{'s' if len(websites) != 1 else ''}",
        'body': f"{len(logs)} checks were evaluated in the selected weekly window.",
    })
    health_overview.append({
        'title': 'Downtime',
        'value': format_duration_value(downtime_duration_seconds),
        'body': f"{outage_frequency} outage incident{'s' if outage_frequency != 1 else ''} were correlated this week.",
    })
    health_overview.append({
        'title': 'Recoveries',
        'value': str(recovery_count),
        'body': 'Recovery alerts confirm when monitored services returned to expected operating conditions.',
    })
    health_overview.append({
        'title': 'Analyzer',
        'value': f"{len(uploads)} upload{'s' if len(uploads) != 1 else ''}",
        'body': f"{analyzer_occurrences} grouped analyzer occurrence{'s' if analyzer_occurrences != 1 else ''} enriched reporting context.",
    })

    insights = []
    insights.append({
        'title': 'Uptime trend',
        'body': f"Average uptime moved from {previous_average_uptime}% in the previous week to {average_uptime}% this week." if previous_logs else f"Average uptime settled at {average_uptime}% for the current week.",
    })
    if most_unstable_site and most_unstable_site['website']:
        insights.append({
            'title': 'Most unstable site',
            'body': f"{most_unstable_site['website'].display_domain} generated {most_unstable_site['issues']} non-UP checks during the week.",
        })
    if slowest_site and slowest_site['website'] and slowest_site['responses']:
        insights.append({
            'title': 'Slowest site',
            'body': f"{slowest_site['website'].display_domain} averaged {round(slowest_site['total_response'] / slowest_site['responses'], 2)}ms across valid responses.",
        })
    if analyzer_occurrences:
        insights.append({
            'title': 'Analyzer pressure',
            'body': f"{analyzer_occurrences} analyzer occurrences were recorded across {len(parsed_errors)} normalized error groups.",
        })

    timeline = []
    for incident in incidents[:8]:
        set_display_domain(incident.website)
        timeline.append({
            'timestamp': incident.started_at,
            'title': incident.title,
            'detail': f"{incident.website.display_domain} incident opened with status {incident.status}.",
            'badge_class': 'badge-down' if not incident.is_resolved else 'badge-up',
            'label': 'Incident',
            'url': reverse('incidents'),
        })
    for alert in alerts[:8]:
        set_display_domain(alert.website)
        timeline.append({
            'timestamp': alert.created_at,
            'title': f"{alert.alert_type} alert for {alert.website.display_domain}",
            'detail': alert.message[:180],
            'badge_class': alert.badge_class,
            'label': 'Alert',
            'url': reverse('alerts'),
        })
    for upload in uploads[:6]:
        timeline.append({
            'timestamp': upload.uploaded_at,
            'title': f"Analyzer upload processed: {upload.filename}",
            'detail': f"{upload.parsed_errors.count()} grouped error signatures available for investigation.",
            'badge_class': 'badge-active',
            'label': 'Analyzer',
            'url': reverse('error_log_results', args=[upload.id]),
        })
    for notification in notifications[:6]:
        timeline.append({
            'timestamp': notification.created_at,
            'title': notification.title,
            'detail': notification.message[:180],
            'badge_class': notification.badge_class,
            'label': 'Notification',
            'url': get_notification_destination(notification),
        })
    timeline.sort(key=lambda item: item['timestamp'], reverse=True)
    timeline = timeline[:12]

    history = []
    current_week_start = get_week_window()[0]
    for offset in range(8):
        history_start = current_week_start - timedelta(days=7 * offset)
        history_end = history_start + timedelta(days=7)
        week_logs = list(
            MonitorLog.objects.filter(
                website__user=user,
                checked_at__gte=history_start,
                checked_at__lt=history_end,
            )
        )
        week_alerts_count = Alert.objects.filter(
            website__user=user,
            created_at__gte=history_start,
            created_at__lt=history_end,
        ).count()
        week_incidents_count = Incident.objects.filter(
            website__user=user,
            started_at__gte=history_start,
            started_at__lt=history_end,
        ).count()
        week_uptime = 0
        if week_logs:
            week_uptime = round((sum(1 for log in week_logs if get_site_status(log) == "UP") / len(week_logs)) * 100, 2)
        history.append({
            'week_key': history_start.strftime('%G-W%V'),
            'label': f"Week of {history_start.strftime('%b %d')}",
            'uptime': week_uptime,
            'alerts': week_alerts_count,
            'incidents': week_incidents_count,
            'url': reverse('weekly_report_detail', args=[history_start.strftime('%G-W%V')]),
            'is_current': history_start == week_start,
        })

    export_rows = [
        {
            'timestamp': item['timestamp'].strftime('%Y-%m-%d %H:%M'),
            'label': item['label'],
            'title': item['title'],
            'detail': item['detail'],
        }
        for item in timeline
    ]

    return {
        'week_key': resolved_week_key,
        'week_start': week_start,
        'week_end': week_end,
        'average_uptime': average_uptime,
        'average_response_time': average_response_time,
        'uptime_delta': round(average_uptime - previous_average_uptime, 2),
        'response_delta': round(average_response_time - previous_average_response_time, 2),
        'downtime_duration': format_duration_value(downtime_duration_seconds),
        'most_unstable_site': most_unstable_site,
        'slowest_site': slowest_site,
        'alert_count': alert_count,
        'incident_count': incident_count,
        'recovery_count': recovery_count,
        'outage_frequency': outage_frequency,
        'uploads_count': len(uploads),
        'analyzer_occurrences': analyzer_occurrences,
        'severity_breakdown': severity_breakdown,
        'health_overview': health_overview,
        'insights': insights[:4],
        'trend_data': _build_weekly_trend(logs, week_start),
        'timeline': timeline,
        'history': history,
        'export_rows': export_rows,
    }


def _build_upload_timeline(uploaded_logs, range_key):
    now = timezone.now()
    if range_key == '24h':
        labels = [
            (now - timedelta(hours=offset)).replace(minute=0, second=0, microsecond=0)
            for offset in range(23, -1, -2)
        ]
        counts = {label: 0 for label in labels}
        for upload in uploaded_logs:
            bucket = upload.uploaded_at.replace(minute=0, second=0, microsecond=0)
            aligned_bucket = bucket.replace(hour=bucket.hour - (bucket.hour % 2))
            if aligned_bucket in counts:
                counts[aligned_bucket] += 1
        return {
            'labels': [label.strftime('%H:%M') for label in labels],
            'counts': [counts[label] for label in labels],
        }

    days = 30 if range_key == '30d' else 7
    start_day = (now - timedelta(days=days - 1)).date()
    labels = [start_day + timedelta(days=index) for index in range(days)]
    counts = {label: 0 for label in labels}
    for upload in uploaded_logs:
        bucket = upload.uploaded_at.date()
        if bucket in counts:
            counts[bucket] += 1
    return {
        'labels': [label.strftime('%b %d') for label in labels],
        'counts': [counts[label] for label in labels],
    }


def _build_error_insights(parsed_errors, uploads, previous_error_total=0):
    insights = []
    total_occurrences = sum(item.count for item in parsed_errors)
    if not parsed_errors:
        return [{
            'title': 'No recent analyzer issues',
            'body': 'Recent uploads did not produce classified error patterns in the selected range.',
        }]

    most_common_error = max(parsed_errors, key=lambda item: item.count)
    insights.append({
        'title': 'Most recurring issue',
        'body': f"{most_common_error.error_type} is the dominant pattern with {most_common_error.count} occurrence{'s' if most_common_error.count != 1 else ''}.",
    })

    dominant_category = Counter(item.category for item in parsed_errors).most_common(1)[0][0]
    dominant_category_label = dict(ParsedError.CATEGORY_CHOICES).get(dominant_category, 'Unknown')
    insights.append({
        'title': 'Primary failure domain',
        'body': f"{dominant_category_label}-related errors account for most of the recent analyzer activity.",
    })

    critical_count = sum(item.count for item in parsed_errors if item.severity == ParsedError.SEVERITY_CRITICAL)
    if critical_count:
        insights.append({
            'title': 'Critical issue pressure',
            'body': f"{critical_count} critical-severity occurrence{'s were' if critical_count != 1 else ' was'} detected across the analyzed uploads.",
        })

    if previous_error_total:
        delta = total_occurrences - previous_error_total
        if delta != 0:
            direction = 'increased' if delta > 0 else 'decreased'
            pct = round((abs(delta) / previous_error_total) * 100) if previous_error_total else 0
            insights.append({
                'title': 'Trend against previous window',
                'body': f"Detected error volume {direction} by {pct}% compared with the previous matching period.",
            })

    if uploads:
        busiest_upload = max(uploads, key=lambda upload: upload.parsed_errors.count())
        if busiest_upload.parsed_errors.exists():
            insights.append({
                'title': 'Noisiest upload',
                'body': f"{busiest_upload.filename} contributed the highest error volume in the current range.",
            })

    return insights[:4]


def _build_notification_groups(page_notifications):
    now = timezone.now()
    grouped = []
    buckets = [
        (
            'Unread',
            'Active monitoring signals awaiting acknowledgement.',
            [item for item in page_notifications if not item.is_read],
        ),
        (
            'Recent Activity',
            'Operational updates from the last 24 hours.',
            [item for item in page_notifications if item.is_read and item.created_at >= now - timedelta(hours=24)],
        ),
        (
            'Earlier Activity',
            'Previously acknowledged updates kept for historical context.',
            [item for item in page_notifications if item.is_read and item.created_at < now - timedelta(hours=24)],
        ),
    ]
    for title, subtitle, items in buckets:
        if items:
            grouped.append({
                'title': title,
                'subtitle': subtitle,
                'items': items,
            })
    return grouped


def _build_alert_preferences_snapshot(websites, alerts_qs, logs_qs):
    logs_by_website = defaultdict(list)
    for log in logs_qs:
        logs_by_website[log.website_id].append(log)

    alerts_by_website = defaultdict(list)
    for alert in alerts_qs:
        alerts_by_website[alert.website_id].append(alert)

    threshold_lookback = timezone.now() - timedelta(hours=24)
    for website in websites:
        website_logs = logs_by_website.get(website.id, [])
        website_alerts = alerts_by_website.get(website.id, [])
        latest_log = website_logs[0] if website_logs else None
        latest_alert = website_alerts[0] if website_alerts else None
        recent_alerts = [alert for alert in website_alerts if alert.created_at >= timezone.now() - timedelta(days=7)]
        recent_recovery = next((alert for alert in website_alerts if alert.alert_type == Alert.TYPE_RECOVERY), None)
        recent_threshold_violations = [
            log for log in website_logs
            if log.checked_at >= threshold_lookback and log.response_time and log.response_time > website.slow_alert_threshold
        ]
        recent_latencies = [log.response_time for log in website_logs[:10] if log.response_time]
        active_cooldown_until = None
        if latest_alert and latest_alert.status in {Alert.STATUS_SENT, Alert.STATUS_PENDING} and latest_alert.alert_type != Alert.TYPE_RECOVERY:
            active_cooldown_until = latest_alert.created_at + ALERT_DEDUP_WINDOW

        website.current_monitoring_state = get_site_status(latest_log)
        website.current_monitoring_badge = (
            'badge-up' if website.current_monitoring_state == MonitorLog.STATUS_UP
            else 'badge-slow' if website.current_monitoring_state == MonitorLog.STATUS_SLOW
            else 'badge-down'
        )
        website.current_average_latency = round(sum(recent_latencies) / len(recent_latencies), 2) if recent_latencies else 0
        website.last_alert_generated_at = latest_alert.created_at if latest_alert else None
        website.last_alert_generated_label = latest_alert.status_label if latest_alert else 'No alerts yet'
        website.last_recovery_at = recent_recovery.created_at if recent_recovery else None
        website.recent_alert_count = len(recent_alerts)
        website.email_delivery_state = (
            'Enabled' if website.email_notifications and website.user.email else 'In-app only'
        )
        website.email_delivery_badge = 'badge-active' if website.email_notifications and website.user.email else 'badge-info'
        website.cooldown_active = bool(active_cooldown_until and active_cooldown_until > timezone.now())
        website.cooldown_until = active_cooldown_until
        website.suppressed_due_to_cooldown = max(website.recent_alert_count - len({alert.alert_type for alert in recent_alerts}), 0)
        website.recent_threshold_violations = len(recent_threshold_violations)

    return websites


def _read_uploaded_log_text(uploaded_log):
    uploaded_log.file.open('rb')
    try:
        return uploaded_log.file.read().decode('utf-8', errors='replace')
    finally:
        uploaded_log.file.close()


def _extract_context_window(lines, first_line, last_line, padding=2):
    if not lines:
        return []
    start = max(first_line - 1 - padding, 0)
    end = min(last_line + padding, len(lines))
    return [
        {
            'number': index + 1,
            'text': lines[index],
        }
        for index in range(start, end)
    ]


def _extract_timestamp(*candidates):
    for candidate in candidates:
        if not candidate:
            continue
        match = TIMESTAMP_RE.search(candidate)
        if match:
            stamp = match.group('stamp')
            return stamp[:5] if len(stamp) >= 5 and stamp[2] == ':' else stamp
    return ''


def _extract_routes_and_services(text):
    routes = []
    services = []
    for line in (text or '').splitlines():
        for match in ROUTE_RE.findall(line):
            if match.startswith('//'):
                continue
            if len(match) > 1 and match not in routes:
                routes.append(match)
        for match in SERVICE_RE.findall(line):
            normalized = match.lower()
            if normalized not in services:
                services.append(normalized)
    return routes[:4], services[:4]


def _line_span_label(first_line, last_line):
    if last_line and last_line != first_line:
        return f"Lines {first_line}-{last_line}"
    return f"Line {first_line}"


def _confidence_for_error(item):
    if item.category != ParsedError.CATEGORY_UNKNOWN and item.count >= 3:
        return 'high'
    if item.category != ParsedError.CATEGORY_UNKNOWN or item.count >= 2:
        return 'medium'
    return 'low'


def _operational_impact_for_error(item):
    if item.severity == ParsedError.SEVERITY_CRITICAL:
        return 'Likely request failures or blocked critical workflows.'
    if item.severity == ParsedError.SEVERITY_HIGH:
        return 'High operator attention required; user-facing degradation is plausible.'
    if item.severity == ParsedError.SEVERITY_MEDIUM:
        return 'Investigate before volume grows or downstream latency compounds.'
    return 'Lower immediate impact, but repeated occurrences may indicate a noisy edge path.'


def _build_investigation_workspace(uploaded_log, parsed_errors):
    log_text = _read_uploaded_log_text(uploaded_log)
    lines = log_text.splitlines()
    occurrences_by_key = defaultdict(list)
    timeline = []

    for entry in iter_error_entries(log_text):
        occurrence_text = "\n".join(
            line['text'] for line in _extract_context_window(lines, entry['first_seen_line'], entry['last_seen_line'], padding=1)
        )
        routes, services = _extract_routes_and_services(occurrence_text)
        occurrence = {
            'first_seen_line': entry['first_seen_line'],
            'last_seen_line': entry['last_seen_line'],
            'line_range_display': _line_span_label(entry['first_seen_line'], entry['last_seen_line']),
            'timestamp': _extract_timestamp(
                lines[entry['first_seen_line'] - 1] if entry['first_seen_line'] - 1 < len(lines) else '',
                occurrence_text,
            ) or f"Line {entry['first_seen_line']}",
            'routes': routes,
            'services': services,
        }
        occurrences_by_key[(entry['error_type'], entry['raw_line'])].append(occurrence)

    previous_line = None
    cluster_index = 0
    for entry in sorted(iter_error_entries(log_text), key=lambda item: (item['first_seen_line'], item['last_seen_line'])):
        diagnostics = get_error_diagnostics(type('AnalyzerEntry', (), entry))
        if previous_line is not None and entry['first_seen_line'] - previous_line > 8:
            cluster_index += 1
        previous_line = entry['last_seen_line']
        timeline.append({
            'timestamp': _extract_timestamp(lines[entry['first_seen_line'] - 1] if entry['first_seen_line'] - 1 < len(lines) else '') or f"Line {entry['first_seen_line']}",
            'title': entry['error_type'],
            'message': entry['raw_line'],
            'severity': diagnostics['severity'],
            'severity_label': dict(ParsedError.SEVERITY_CHOICES).get(diagnostics['severity'], 'Low'),
            'severity_badge_class': {
                ParsedError.SEVERITY_CRITICAL: 'badge-down',
                ParsedError.SEVERITY_HIGH: 'badge-slow',
                ParsedError.SEVERITY_MEDIUM: 'badge-purple',
                ParsedError.SEVERITY_LOW: 'badge-info',
            }.get(diagnostics['severity'], 'badge-info'),
            'line_range_display': _line_span_label(entry['first_seen_line'], entry['last_seen_line']),
            'cluster_index': cluster_index,
        })

    investigation_groups = []
    affected_routes = []
    affected_services = []
    all_next_actions = []
    for index, item in enumerate(parsed_errors):
        diagnostics = get_error_diagnostics(item)
        occurrences = occurrences_by_key.get((item.error_type, item.raw_line), [])
        context_lines = _extract_context_window(lines, item.first_seen_line, item.last_seen_line, padding=3)
        traceback_text = "\n".join(
            f"{line['number']:>4} | {line['text']}" for line in context_lines
        )
        routes, services = _extract_routes_and_services(traceback_text)
        for route in routes:
            if route not in affected_routes:
                affected_routes.append(route)
        for service in services:
            if service not in affected_services:
                affected_services.append(service)
        all_next_actions.extend(diagnostics['suggested_checks'][:2])
        confidence_key = _confidence_for_error(item)
        first_seen_label = occurrences[0]['timestamp'] if occurrences else f"Line {item.first_seen_line}"
        last_seen_label = occurrences[-1]['timestamp'] if occurrences else f"Line {item.last_seen_line}"
        investigation_groups.append({
            'id': f"error-group-{index}",
            'item': item,
            'occurrences': occurrences,
            'affected_routes': routes or [occurrence_route for occurrence in occurrences for occurrence_route in occurrence['routes']][:4],
            'affected_services': services or [occurrence_service for occurrence in occurrences for occurrence_service in occurrence['services']][:4],
            'confidence_key': confidence_key,
            'confidence_label': CONFIDENCE_COPY[confidence_key],
            'operational_impact': _operational_impact_for_error(item),
            'first_seen_label': first_seen_label,
            'last_seen_label': last_seen_label,
            'traceback_text': traceback_text or item.raw_line,
            'traceback_preview': traceback_text.splitlines()[:4],
            'default_open': index == 0,
            'search_blob': " ".join([
                item.error_type,
                item.raw_line,
                item.category_label,
                item.severity_label,
                diagnostics['probable_cause'],
            ]).lower(),
            'related_occurrence_count': len(occurrences),
        })

    severity_counter = Counter(item.severity for item in parsed_errors)
    top_error = parsed_errors[0] if parsed_errors else None
    likely_root_cause = top_error.probable_cause if top_error else 'No classified issue patterns were detected in this upload.'
    if parsed_errors:
        highest_severity = next(
            (
                label for key, label in ParsedError.SEVERITY_CHOICES
                if severity_counter.get(key, 0)
            ),
            'Low',
        )
    else:
        highest_severity = 'Low'

    smart_panels = [
        {
            'title': 'Systems affected',
            'value': ", ".join((affected_services + affected_routes)[:4]) or 'Application runtime',
            'body': 'Derived from traceback context, routes, and subsystem keywords already present in the uploaded log.',
        },
        {
            'title': 'Likely root cause',
            'value': likely_root_cause,
            'body': 'Based on the most dominant classified signature and the deterministic diagnostics rules.',
        },
        {
            'title': 'Confidence level',
            'value': CONFIDENCE_COPY[_confidence_for_error(top_error)] if top_error else 'Low confidence',
            'body': 'Confidence increases when the same classified signature repeats across multiple occurrences.',
        },
        {
            'title': 'Operational impact',
            'value': highest_severity,
            'body': _operational_impact_for_error(top_error) if top_error else 'No active impact inferred from this upload.',
        },
        {
            'title': 'Recommended next actions',
            'value': ", ".join(list(dict.fromkeys(all_next_actions))[:3]) or 'Upload a richer traceback sample for more context.',
            'body': 'These checks are deterministic suggestions aggregated from the visible classified failures.',
        },
    ]

    return {
        'timeline_events': timeline,
        'investigation_groups': investigation_groups,
        'smart_panels': smart_panels,
    }


def build_error_report_analytics(user, range_start, range_key):
    uploads = list(
        UploadedLog.objects.filter(user=user, uploaded_at__gte=range_start)
        .prefetch_related('parsed_errors')
        .order_by('-uploaded_at', '-id')
    )
    parsed_errors = list(
        ParsedError.objects.filter(uploaded_log__user=user, uploaded_log__uploaded_at__gte=range_start)
        .select_related('uploaded_log')
        .order_by('-count', 'first_seen_line', 'id')
    )

    previous_window_start = range_start - (timezone.now() - range_start)
    previous_error_total = ParsedError.objects.filter(
        uploaded_log__user=user,
        uploaded_log__uploaded_at__gte=previous_window_start,
        uploaded_log__uploaded_at__lt=range_start,
    ).aggregate(total=Sum('count'))['total'] or 0

    severity_rows = [
        {
            'key': severity_key,
            'label': severity_label,
            'count': sum(item.count for item in parsed_errors if item.severity == severity_key),
        }
        for severity_key, severity_label in ParsedError.SEVERITY_CHOICES
    ]
    category_rows = [
        {
            'key': category_key,
            'label': category_label,
            'count': sum(item.count for item in parsed_errors if item.category == category_key),
        }
        for category_key, category_label in ParsedError.CATEGORY_CHOICES
    ]
    recurring_rows = []
    aggregated_recurring = defaultdict(int)
    for item in parsed_errors:
        aggregated_recurring[item.error_type] += item.count
    for error_type, total_count in sorted(aggregated_recurring.items(), key=lambda pair: (-pair[1], pair[0].lower()))[:5]:
        recurring_rows.append({'label': error_type, 'count': total_count})

    top_errors = parsed_errors[:5]
    upload_timeline = _build_upload_timeline(uploads, range_key)
    total_occurrences = sum(item.count for item in parsed_errors)

    return {
        'has_data': bool(parsed_errors),
        'uploads_count': len(uploads),
        'error_groups_count': len(parsed_errors),
        'total_occurrences': total_occurrences,
        'severity_rows': severity_rows,
        'category_rows': [row for row in category_rows if row['count']],
        'recurring_rows': recurring_rows,
        'top_errors': top_errors,
        'upload_timeline': upload_timeline,
        'insights': _build_error_insights(parsed_errors, uploads, previous_error_total=previous_error_total),
    }


def build_error_analyzer_summary(uploaded_log):
    analytics = build_upload_analytics(uploaded_log)
    parsed_errors = analytics['parsed_errors']
    severity_counts = Counter(item.severity for item in parsed_errors)
    category_counts = Counter(item.category for item in parsed_errors)
    severity_rows = [
        {
            'key': severity_key,
            'label': severity_label,
            'count': severity_counts.get(severity_key, 0),
        }
        for severity_key, severity_label in ParsedError.SEVERITY_CHOICES
    ]
    category_rows = [
        {
            'key': category_key,
            'label': category_label,
            'count': category_counts.get(category_key, 0),
        }
        for category_key, category_label in ParsedError.CATEGORY_CHOICES
        if category_counts.get(category_key, 0)
    ]
    for item in parsed_errors:
        diagnostics = get_error_diagnostics(item)
        item.probable_cause = diagnostics['probable_cause']
        item.suggested_checks = diagnostics['suggested_checks']
        item.remediation_tips = diagnostics['remediation_tips']

    analytics['severity_rows'] = severity_rows
    analytics['category_rows'] = category_rows
    analytics['insights'] = _build_error_insights(parsed_errors, [uploaded_log])
    analytics.update(_build_investigation_workspace(uploaded_log, parsed_errors))
    return analytics


def build_error_analyzer_workspace_summary(user):
    uploads_qs = UploadedLog.objects.filter(user=user).prefetch_related('parsed_errors').order_by('-uploaded_at', '-id')
    recent_uploads = list(uploads_qs[:10])
    all_parsed_errors = list(
        ParsedError.objects.filter(uploaded_log__user=user).select_related('uploaded_log').order_by('-count', 'first_seen_line', 'id')
    )
    total_uploads = uploads_qs.count()
    processed_uploads = uploads_qs.filter(processed=True).count()
    total_occurrences = sum(item.count for item in all_parsed_errors)
    top_errors = sorted(all_parsed_errors, key=lambda item: (-item.count, item.error_type))[:5]
    severity_counter = Counter(item.severity for item in all_parsed_errors)
    category_counter = Counter(item.category for item in all_parsed_errors)

    return {
        'recent_uploads': recent_uploads,
        'workspace_upload_count': UploadedLog.objects.filter(user=user).count(),
        'workspace_processed_count': processed_uploads,
        'workspace_total_occurrences': total_occurrences,
        'workspace_error_groups': ParsedError.objects.filter(uploaded_log__user=user).count(),
        'workspace_top_errors': top_errors,
        'workspace_severity_rows': [
            {'key': key, 'label': label, 'count': severity_counter.get(key, 0)}
            for key, label in ParsedError.SEVERITY_CHOICES
        ],
        'workspace_category_rows': [
            {'key': key, 'label': label, 'count': category_counter.get(key, 0)}
            for key, label in ParsedError.CATEGORY_CHOICES
            if category_counter.get(key, 0)
        ],
        'workspace_insights': _build_error_insights(all_parsed_errors, recent_uploads),
    }


# ✅ STATUS HELPER
def ensure_admin_user():
    if not django_settings.BOOTSTRAP_ADMIN_ENABLED:
        return

    if not _auth_user_table_ready():
        return

    try:
        if not User.objects.filter(username='admin').exists():
            User.objects.create_superuser(
                username='admin',
                password='admin123',
                email='admin@example.com',
            )
    except (OperationalError, ProgrammingError):
        logger.warning("Skipping admin bootstrap because database migrations are not ready.", exc_info=True)


def ensure_internal_user(request):
    if not request.user.is_staff and not request.user.is_superuser:
        raise Http404()


def _ops_badge_class(state):
    return {
        'healthy': 'badge-up',
        'warning': 'badge-slow',
        'critical': 'badge-down',
        'info': 'badge-info',
        'active': 'badge-active',
    }.get(state, 'badge-purple')


def _ops_icon_classes(state):
    return {
        'healthy': 'bg-good-light text-good',
        'warning': 'bg-warning-light text-warning',
        'critical': 'bg-critical-light text-critical',
        'info': 'bg-info-light text-info-tone',
        'active': 'bg-active-light text-active',
    }.get(state, 'bg-panel-light text-white')


def _build_ops_status_card(*, label, state, summary, detail, icon):
    return {
        'label': label,
        'state': state,
        'summary': summary,
        'detail': detail,
        'icon': icon,
        'badge_class': _ops_badge_class(state),
        'icon_classes': _ops_icon_classes(state),
    }


def _build_ops_metric(*, label, value, detail='', tone='info'):
    return {
        'label': label,
        'value': value,
        'detail': detail,
        'badge_class': _ops_badge_class(tone),
    }


def _format_latency(value):
    if value is None:
        return 'No data'
    return f'{round(value, 2):g} ms'


def _compute_percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    index = min(max(math.ceil(len(ordered) * percentile) - 1, 0), len(ordered) - 1)
    return round(ordered[index], 2)


@lru_cache(maxsize=1)
def _get_git_commit_hash():
    env_commit = (
        os.environ.get('RENDER_GIT_COMMIT')
        or os.environ.get('GIT_COMMIT')
        or os.environ.get('COMMIT_SHA')
        or ''
    ).strip()
    if env_commit:
        return env_commit[:12]

    try:
        completed = subprocess.run(
            ['git', 'rev-parse', '--short=12', 'HEAD'],
            cwd=django_settings.BASE_DIR,
            capture_output=True,
            check=True,
            text=True,
        )
    except Exception:
        return 'unavailable'

    return (completed.stdout or '').strip() or 'unavailable'


def _get_app_version():
    configured_version = (
        os.environ.get('APP_VERSION')
        or os.environ.get('RENDER_SERVICE_VERSION')
        or os.environ.get('RELEASE_VERSION')
        or ''
    ).strip()
    if configured_version:
        return configured_version
    return _get_git_commit_hash()


def _get_environment_name():
    configured_environment = (
        os.environ.get('ENVIRONMENT_NAME')
        or os.environ.get('ENVIRONMENT')
        or os.environ.get('RENDER_ENVIRONMENT')
        or ''
    ).strip()
    if configured_environment:
        return configured_environment
    return 'development' if django_settings.DEBUG else 'production'


def _get_scheduler_interval_minutes():
    try:
        interval = int(os.environ.get('MONITOR_SCHEDULE_MINUTES', '5'))
    except ValueError:
        return 5
    return max(interval, 1)


def _build_operational_health_context():
    now = timezone.now()
    windows = {
        '24h': now - timedelta(hours=24),
        '7d': now - timedelta(days=7),
        '30d': now - timedelta(days=30),
    }
    scheduler_interval_minutes = _get_scheduler_interval_minutes()
    monitor_logs = list(
        MonitorLog.objects.filter(checked_at__gte=windows['30d']).only(
            'status',
            'response_time',
            'checked_at',
            'website_id',
        )
    )
    recent_monitor_history = list(
        MonitorLog.objects.select_related('website', 'website__user').order_by('-checked_at', '-id')[:12]
    )
    for log in recent_monitor_history:
        log.display_domain = normalize_domain_display(log.website.url)
        log.resolved_status = get_site_status(log)
        log.response_time_display = _format_latency(log.response_time if log.response_time else None)

    monitor_windows = {
        key: {'total': 0, 'up': 0, 'failed': 0, 'latencies': []}
        for key in windows
    }
    for log in monitor_logs:
        resolved_status = get_site_status(log)
        for window_key, start_time in windows.items():
            if log.checked_at < start_time:
                continue
            monitor_windows[window_key]['total'] += 1
            if resolved_status == MonitorLog.STATUS_UP:
                monitor_windows[window_key]['up'] += 1
            if resolved_status == MonitorLog.STATUS_DOWN:
                monitor_windows[window_key]['failed'] += 1
            if log.response_time and log.response_time > 0:
                monitor_windows[window_key]['latencies'].append(float(log.response_time))

    uptime_metrics = []
    for window_key, label in (('24h', '24h'), ('7d', '7d'), ('30d', '30d')):
        total = monitor_windows[window_key]['total']
        up = monitor_windows[window_key]['up']
        uptime_value = round((up / total) * 100, 2) if total else None
        tone = 'healthy' if uptime_value is not None and uptime_value >= 99 else 'warning'
        if uptime_value is None:
            tone = 'info'
        uptime_metrics.append(
            _build_ops_metric(
                label=f'Uptime {label}',
                value=f'{uptime_value:g}%' if uptime_value is not None else 'No data',
                detail=f'{total} checks evaluated' if total else 'No monitor executions recorded in this window.',
                tone=tone,
            )
        )

    latency_metrics = [
        _build_ops_metric(
            label='Latency Avg 24h',
            value=_format_latency(
                (
                    round(sum(monitor_windows['24h']['latencies']) / len(monitor_windows['24h']['latencies']), 2)
                    if monitor_windows['24h']['latencies'] else None
                )
            ),
            detail='Average successful monitor response time in the last 24 hours.',
            tone='healthy' if monitor_windows['24h']['latencies'] else 'info',
        ),
        _build_ops_metric(
            label='Latency P95 24h',
            value=_format_latency(_compute_percentile(monitor_windows['24h']['latencies'], 0.95)),
            detail='95th percentile successful response time in the last 24 hours.',
            tone='healthy' if monitor_windows['24h']['latencies'] else 'info',
        ),
        _build_ops_metric(
            label='Latency P99 7d',
            value=_format_latency(_compute_percentile(monitor_windows['7d']['latencies'], 0.99)),
            detail='99th percentile successful response time in the last 7 days.',
            tone='healthy' if monitor_windows['7d']['latencies'] else 'info',
        ),
    ]

    database_state = 'healthy'
    database_summary = 'Database query path is responding.'
    database_detail = 'Auth and monitoring tables are reachable.'
    try:
        with connection.cursor() as cursor:
            cursor.execute('SELECT 1')
            cursor.fetchone()
        auth_user_present = User._meta.db_table in set(connection.introspection.table_names())
        if not auth_user_present:
            database_state = 'warning'
            database_summary = 'Database is reachable, but auth tables look incomplete.'
            database_detail = 'Run migrations before trusting this deployment.'
    except Exception as exc:
        database_state = 'critical'
        database_summary = 'Database connectivity probe failed.'
        database_detail = str(exc)

    cloudinary_config = getattr(django_settings, 'CLOUDINARY_STORAGE', {}) or {}
    default_storage_backend = (
        getattr(django_settings, 'STORAGES', {}).get('default', {}).get('BACKEND', '')
    )
    cloudinary_configured = all(
        cloudinary_config.get(key)
        for key in ('CLOUD_NAME', 'API_KEY', 'API_SECRET')
    )
    if 'cloudinary' in default_storage_backend.lower() and cloudinary_configured:
        cloudinary_card = _build_ops_status_card(
            label='Cloudinary',
            state='healthy',
            summary='Cloudinary media storage is configured.',
            detail=f'Backend: {default_storage_backend}',
            icon='cloud',
        )
    elif 'filesystemstorage' in default_storage_backend.lower():
        cloudinary_card = _build_ops_status_card(
            label='Cloudinary',
            state='warning',
            summary='Local filesystem media storage is active.',
            detail='Expected for development. Production should use Cloudinary-backed storage.',
            icon='cloud-off',
        )
    else:
        cloudinary_card = _build_ops_status_card(
            label='Cloudinary',
            state='critical',
            summary='Cloudinary storage is not fully configured.',
            detail=f'Backend: {default_storage_backend or "unset"}',
            icon='cloud-off',
        )

    email_diagnostics = get_email_diagnostics()
    latest_email_alert = Alert.objects.filter(
        Q(sent_to__gt='') | Q(status=Alert.STATUS_FAILED)
    ).select_related('website', 'incident').order_by('-created_at', '-id').first()
    brevo_state = 'healthy' if email_diagnostics['configured'] and email_diagnostics['using_brevo_api'] else 'warning'
    brevo_summary = 'Brevo API transport is configured.'
    if not email_diagnostics['using_brevo_api']:
        brevo_summary = 'Email transport is not using the Brevo API backend.'
    if not email_diagnostics['configured']:
        brevo_state = 'critical'
        brevo_summary = 'Email transport configuration is incomplete.'
    if latest_email_alert and latest_email_alert.status == Alert.STATUS_FAILED:
        brevo_state = 'warning' if email_diagnostics['configured'] else 'critical'
        brevo_summary = 'Latest alert email delivery failed.'
    brevo_card = _build_ops_status_card(
        label='Brevo Email',
        state=brevo_state,
        summary=brevo_summary,
        detail=(
            f"Backend: {email_diagnostics['backend'] or 'unset'} | "
            f"Provider: {email_diagnostics['provider']}"
        ),
        icon='mail',
    )

    latest_checked_at = recent_monitor_history[0].checked_at if recent_monitor_history else None
    scheduler_tolerance = timedelta(minutes=scheduler_interval_minutes * 3)
    scheduler_warning_tolerance = timedelta(minutes=scheduler_interval_minutes * 6)
    if latest_checked_at is None:
        scheduler_card = _build_ops_status_card(
            label='Scheduler',
            state='info',
            summary='No monitor executions have been recorded yet.',
            detail=f'Expected cadence is every {scheduler_interval_minutes} minutes.',
            icon='clock-3',
        )
    else:
        age = now - latest_checked_at
        scheduler_state = 'healthy'
        scheduler_summary = 'Monitor scheduler is within the expected execution window.'
        if age > scheduler_warning_tolerance:
            scheduler_state = 'critical'
            scheduler_summary = 'Monitor scheduler looks stalled.'
        elif age > scheduler_tolerance:
            scheduler_state = 'warning'
            scheduler_summary = 'Monitor scheduler is running late.'
        scheduler_card = _build_ops_status_card(
            label='Scheduler',
            state=scheduler_state,
            summary=scheduler_summary,
            detail=(
                f'Last monitor log recorded {format_duration_value(age.total_seconds())} ago. '
                f'Expected cadence: every {scheduler_interval_minutes} minutes.'
            ),
            icon='timer',
        )

    unresolved_alerts_count = Alert.objects.filter(is_read=False).exclude(
        alert_type=Alert.TYPE_RECOVERY
    ).count()
    failed_alert_sends_count = Alert.objects.filter(
        status=Alert.STATUS_FAILED,
        created_at__gte=windows['7d'],
    ).count()
    active_incidents_count = Incident.objects.filter(is_resolved=False).count()

    recent_exceptions = list(
        ParsedError.objects.select_related('uploaded_log', 'uploaded_log__user').order_by(
            '-uploaded_log__uploaded_at', '-count', '-id'
        )[:8]
    )

    latest_email_result = None
    if latest_email_alert is not None:
        latest_email_alert.display_domain = normalize_domain_display(latest_email_alert.website.url)
        latest_email_result = {
            'state': 'healthy' if latest_email_alert.status == Alert.STATUS_SENT else 'critical',
            'status': latest_email_alert.status,
            'website': latest_email_alert.display_domain,
            'created_at': latest_email_alert.created_at,
            'recipient': latest_email_alert.sent_to or 'No recipient recorded',
            'message': latest_email_alert.message,
            'badge_class': _ops_badge_class(
                'healthy' if latest_email_alert.status == Alert.STATUS_SENT else 'critical'
            ),
        }

    return {
        'component_health_cards': [
            _build_ops_status_card(
                label='Database',
                state=database_state,
                summary=database_summary,
                detail=database_detail,
                icon='database',
            ),
            cloudinary_card,
            brevo_card,
            scheduler_card,
        ],
        'summary_metrics': [
            _build_ops_metric(
                label='Monitored Sites',
                value=str(Website.objects.count()),
                detail='Total websites currently tracked across all accounts.',
                tone='active',
            ),
            _build_ops_metric(
                label='Active Incidents',
                value=str(active_incidents_count),
                detail='Incidents still open right now.',
                tone='critical' if active_incidents_count else 'healthy',
            ),
            _build_ops_metric(
                label='Unresolved Alerts',
                value=str(unresolved_alerts_count),
                detail='Unread alerts excluding recovery notices.',
                tone='warning' if unresolved_alerts_count else 'healthy',
            ),
            _build_ops_metric(
                label='Failed Alert Sends',
                value=str(failed_alert_sends_count),
                detail='Failed alert deliveries over the last 7 days.',
                tone='critical' if failed_alert_sends_count else 'healthy',
            ),
            _build_ops_metric(
                label='Failed Monitor Runs',
                value=str(monitor_windows['24h']['failed']),
                detail='DOWN results captured over the last 24 hours.',
                tone='critical' if monitor_windows['24h']['failed'] else 'healthy',
            ),
        ],
        'uptime_metrics': uptime_metrics,
        'latency_metrics': latency_metrics,
        'recent_monitor_history': recent_monitor_history,
        'recent_exceptions': recent_exceptions,
        'latest_email_result': latest_email_result,
        'release_metadata': {
            'app_version': _get_app_version(),
            'git_commit': _get_git_commit_hash(),
            'environment_name': _get_environment_name(),
            'settings_module': django_settings.SETTINGS_MODULE,
            'last_monitor_check': latest_checked_at,
        },
        'ops_refresh_seconds': scheduler_interval_minutes * 60,
    }


def index(request):
    return render(request, 'monitor/index.html')


def custom_404(request, exception):
    try:
        return render(request, 'errors/404.html', status=404)
    except Exception:
        return HttpResponse("Not Found", status=404, content_type="text/plain")


def custom_500(request):
    try:
        return render(request, 'errors/500.html', status=500)
    except Exception:
        return HttpResponse("Internal Server Error", status=500, content_type="text/plain")


@require_GET
def health_check(request):
    db_ok = False
    auth_user_present = False
    try:
        table_names = set(connection.introspection.table_names())
        db_ok = True
        auth_user_present = User._meta.db_table in table_names
    except (OperationalError, ProgrammingError):
        logger.exception("Health check database inspection failed.")

    payload = {
        'status': 'ok' if db_ok and auth_user_present else 'degraded',
        'database': db_ok,
        'auth_user_table': auth_user_present,
        'settings_module': django_settings.SETTINGS_MODULE,
        'debug': django_settings.DEBUG,
    }
    status_code = 200 if payload['status'] == 'ok' else 503
    return JsonResponse(payload, status=status_code)


@require_GET
def internal_monitoring_trigger(request, token):
    secret = (django_settings.CRON_SECRET or '').strip()
    if not secret or not compare_digest(token, secret):
        raise Http404()

    command_output = StringIO()
    call_command('monitor_sites', stdout=command_output)
    return HttpResponse(command_output.getvalue() or 'Monitoring run complete.\n', content_type='text/plain')


def login(request):
    try:
        ensure_admin_user()
        if request.user.is_authenticated:
            return redirect('dashboard')

        form = LoginForm(request.POST or None)
        if request.method == 'POST' and form.is_valid():
            user = authenticate(
                request,
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password'],
            )
            if user is not None:
                auth_login(request, user)
                return redirect('dashboard')
            form.add_error(None, 'Invalid username or password.')

        return render(request, 'monitor/login.html', {'form': form})
    except Exception:
        logger.exception("Failed to render or process login view.")
        raise


def signup(request):
    try:
        ensure_admin_user()
        if request.user.is_authenticated:
            return redirect('dashboard')

        form = SignUpForm(request.POST or None)
        if request.method == 'POST' and form.is_valid():
            form.save()
            return redirect('login')

        return render(request, 'monitor/signup.html', {'form': form})
    except Exception:
        logger.exception("Failed to render or process signup view.")
        raise


def logout_view(request):
    auth_logout(request)
    return redirect('login')


@login_required
def operations_dashboard(request):
    ensure_internal_user(request)
    context = _build_operational_health_context()
    return render(request, 'monitor/operations_dashboard.html', context)


# ✅ DASHBOARD (FULL FIXED)
@login_required
def dashboard(request):
    ensure_admin_user()
    Website.cleanup_existing(user=request.user)
    cleanup_monitoring_state(user=request.user)

    websites = list(Website.objects.filter(user=request.user).order_by('-created_at'))
    website_ids = [website.id for website in websites]

    all_logs = list(MonitorLog.objects.filter(
        website_id__in=website_ids
    ).select_related('website').order_by('-checked_at'))

    latest_logs = get_latest_logs_by_website(all_logs)

    # ✅ FIXED LOGS (NO TRUE ISSUE)
    logs = []
    for log in all_logs[:20]:
        logs.append({
            'url': log.website.url,
            'display_domain': normalize_domain_display(log.website.url),
            'status': get_site_status(log),
            'response_time': round(log.response_time, 2) if log.response_time is not None else 0,
            'checked_at': log.checked_at,
        })

    # ✅ FIXED SITES
    for website in websites:
        snapshot = get_site_snapshot(latest_logs.get(website.id))
        website.status = snapshot['status']
        website.response_time = snapshot['response_time']
        website.last_checked = snapshot['last_checked']
        website.display_domain = normalize_domain_display(website.url)
        website.favicon = get_favicon_url(website.url)
        website.ssl_status = check_ssl_status(website.url)

    # ✅ FIXED TOP STATUS (NO TRUE)
    status = "UP"
    response_time = 0

    if latest_logs:
        statuses = [get_site_status(log) for log in latest_logs.values()]
        valid_response_times = get_valid_response_times(latest_logs.values())

        if "DOWN" in statuses:
            status = "DOWN"
        elif "SLOW" in statuses:
            status = "SLOW"
        else:
            status = "UP"

        if valid_response_times:
            response_time = round(
                sum(valid_response_times) / len(valid_response_times),
                2
            )

    total_logs = len(all_logs)
    up_logs = sum(1 for log in all_logs if log.status == MonitorLog.STATUS_UP)

    uptime = (up_logs / total_logs) * 100 if total_logs > 0 else 0
    incidents = Incident.objects.filter(
        website__user=request.user,
        is_resolved=False,
    ).count()

    # ⚠️ IMPORTANT FIX HERE
    has_slow = any(site.status == "SLOW" for site in websites)

    context = {
        'sites': websites,
        'logs': logs,
        'status': status,
        'response_time': response_time,
        'uptime': round(uptime, 2),
        'incidents': incidents,
        'has_slow': has_slow,
    }

    return render(request, 'monitor/dashboard.html', context)


@login_required
def dashboard_data(request):
    Website.cleanup_existing(user=request.user)
    cleanup_monitoring_state(user=request.user)
    sites = list(Website.objects.filter(user=request.user).order_by('-created_at'))
    website_ids = [site.id for site in sites]
    all_logs = MonitorLog.objects.filter(
        website_id__in=website_ids
    ).order_by('-checked_at')
    latest_logs = get_latest_logs_by_website(all_logs)
    data = []

    for site in sites:
        snapshot = get_site_snapshot(latest_logs.get(site.id))
        site.display_domain = normalize_domain_display(site.url)

        data.append({
            'id': site.id,
            'url': site.url,
            'display_domain': site.display_domain,
            'status': snapshot['status'],
            'response_time': snapshot['response_time'],
            'last_checked': snapshot['last_checked'].strftime('%Y-%m-%d %H:%M') if snapshot['last_checked'] else '',
        })

    return JsonResponse({'sites': data})


@login_required
def status(request):
    Website.cleanup_existing(user=request.user)
    cleanup_monitoring_state(user=request.user)
    websites = list(Website.objects.filter(user=request.user).order_by('-created_at'))
    website_ids = [website.id for website in websites]
    latest_logs = get_latest_logs_by_website(MonitorLog.objects.filter(
        website_id__in=website_ids
    ).order_by('-checked_at'))

    for site in websites:
        snapshot = get_site_snapshot(latest_logs.get(site.id))
        site.status = snapshot['status']
        site.response_time = snapshot['response_time']
        site.last_checked = snapshot['last_checked']
        site.display_domain = normalize_domain_display(site.url)
        site.favicon = get_favicon_url(site.url)
        site.ssl_status = check_ssl_status(site.url)

    return render(request, 'monitor/status.html', {'sites': websites})


@login_required
@require_POST
def check_now(request, website_id):
    website = get_object_or_404(
        Website,
        id=website_id,
        user=request.user,
    )

    try:
        run_single_check(website)
    except Exception:
        logger.exception(
            "Manual monitoring check failed.",
            extra={"website_id": website.id, "user_id": request.user.id},
        )
        messages.warning(
            request,
            f"Check started for {website.url}, but the verification run did not complete successfully.",
        )
    else:
        messages.success(request, f"Checked {website.url}")
    return redirect('status')


@login_required
def reports(request):
    range_key = request.GET.get('range', '7d')
    if range_key not in {'24h', '7d', '30d'}:
        range_key = '7d'

    ensure_weekly_report_notification(request.user)
    context = build_reports_context(request.user, range_key)
    context['ai_report_state'] = get_report_ai_state(request.user, context)
    return render(request, 'monitor/reports.html', context)


@login_required
@require_POST
def generate_report_ai_analysis(request):
    range_key = request.POST.get('range', '7d')
    if range_key not in {'24h', '7d', '30d'}:
        range_key = '7d'
    context = build_reports_context(request.user, range_key)
    cache = generate_report_analysis(
        request.user,
        context,
        force=request.POST.get('force') == '1',
    )
    if cache.status == cache.STATUS_READY:
        messages.success(request, 'AI report intelligence generated.')
    elif cache.status == cache.STATUS_DISABLED:
        messages.warning(request, 'AI operational intelligence is disabled for this environment.')
    else:
        messages.warning(request, 'AI report intelligence could not be generated. The report remains available.')
    return redirect(f"{reverse('reports')}?range={range_key}")


@login_required
def weekly_reports(request, week_key=None):
    ensure_weekly_report_notification(request.user)
    context = build_weekly_report_context(request.user, week_key=week_key)
    return render(request, 'monitor/weekly_report.html', context)


@login_required
def error_log_upload(request):
    if request.method == 'POST':
        form = UploadedLogForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_log = form.save(commit=False)
            uploaded_log.user = request.user
            uploaded_log.filename = form.cleaned_data['file'].name
            uploaded_log.processed = False
            uploaded_log.save()
            process_uploaded_log(uploaded_log)
            messages.success(request, f'Processed {uploaded_log.filename} successfully.')
            return redirect('error_log_results', upload_id=uploaded_log.id)
        messages.error(request, 'Upload failed. Review the selected file and try again.')
    else:
        form = UploadedLogForm()

    workspace_summary = build_error_analyzer_workspace_summary(request.user)
    context = {
        'form': form,
        **workspace_summary,
    }
    return render(request, 'monitor/error_log_upload.html', context)


@login_required
def error_log_results(request, upload_id):
    uploaded_log = get_object_or_404(
        UploadedLog.objects.prefetch_related('parsed_errors'),
        id=upload_id,
        user=request.user,
    )
    summary = build_error_analyzer_summary(uploaded_log)
    recent_uploads = UploadedLog.objects.filter(user=request.user).exclude(id=uploaded_log.id).order_by('-uploaded_at', '-id')[:8]
    workspace_summary = build_error_analyzer_workspace_summary(request.user)

    context = {
        'uploaded_log': uploaded_log,
        'recent_uploads': recent_uploads,
        'workspace_insights': workspace_summary['workspace_insights'],
        'ai_error_state': get_error_upload_ai_state(request.user, uploaded_log, summary),
        **summary,
    }
    return render(request, 'monitor/error_log_results.html', context)


@login_required
@require_POST
def generate_error_upload_ai_analysis(request, upload_id):
    uploaded_log = get_object_or_404(
        UploadedLog.objects.prefetch_related('parsed_errors'),
        id=upload_id,
        user=request.user,
    )
    summary = build_error_analyzer_summary(uploaded_log)
    cache = generate_error_upload_analysis(
        request.user,
        uploaded_log,
        summary,
        force=request.POST.get('force') == '1',
    )
    if cache.status == cache.STATUS_READY:
        messages.success(request, 'AI error explanation generated.')
    elif cache.status == cache.STATUS_DISABLED:
        messages.warning(request, 'AI operational intelligence is disabled for this environment.')
    else:
        messages.warning(request, 'AI error explanation could not be generated. Analyzer results remain available.')
    return redirect('error_log_results', upload_id=upload_id)


@login_required
def incidents(request):
    cleanup_monitoring_state(user=request.user)
    incidents = list(Incident.objects.filter(
        website__user=request.user
    ).select_related('website').prefetch_related('events').order_by('-started_at', '-created_at'))
    for incident in incidents:
        set_display_domain(incident.website)

    week_ago = timezone.now() - timedelta(days=7)
    active_incidents = sum(1 for incident in incidents if not incident.is_resolved)
    resolved_this_week = sum(
        1 for incident in incidents
        if incident.is_resolved and incident.resolved_at and incident.resolved_at >= week_ago
    )

    resolved_incidents = [
        incident for incident in incidents
        if incident.is_resolved and incident.resolved_at is not None
    ]
    average_resolution_time = "0m"
    if resolved_incidents:
        average_seconds = sum(
            max(int((incident.resolved_at - incident.started_at).total_seconds()), 0)
            for incident in resolved_incidents
        ) / len(resolved_incidents)
        average_resolution_time = format_duration_value(average_seconds)

    incident_cache = {
        cache.scope_key: cache
        for cache in request.user.ai_analysis_cache.filter(scope='incident')
    }
    for incident in incidents:
        incident.ai_state = get_incident_ai_state(
            request.user,
            incident,
            cache=incident_cache.get(f"incident:{incident.id}"),
        )

    context = {
        'incidents': incidents,
        'active_incidents': active_incidents,
        'resolved_this_week': resolved_this_week,
        'average_resolution_time': average_resolution_time,
    }
    return render(request, 'monitor/incidents.html', context)


@login_required
@require_POST
def generate_incident_ai_analysis(request, incident_id):
    incident = get_object_or_404(
        Incident.objects.select_related('website').prefetch_related('events'),
        id=incident_id,
        website__user=request.user,
    )
    cache = generate_incident_analysis(
        request.user,
        incident,
        force=request.POST.get('force') == '1',
    )
    if cache.status == cache.STATUS_READY:
        messages.success(request, 'AI incident analysis generated.')
    elif cache.status == cache.STATUS_DISABLED:
        messages.warning(request, 'AI operational intelligence is disabled for this environment.')
    else:
        messages.warning(request, 'AI incident analysis could not be generated. Incident history remains available.')
    return redirect('incidents')


@login_required
def logs(request):
    cleanup_monitoring_state(user=request.user)
    logs_qs = MonitorLog.objects.filter(
        website__user=request.user
    ).select_related('website').order_by('-checked_at')[:100]
    logs_data = [serialize_log(log) for log in logs_qs]

    context = {
        'logs': logs_data,
        'down_count': sum(1 for log in logs_data if log['status'] == 'DOWN'),
        'slow_count': sum(1 for log in logs_data if log['status'] == 'SLOW'),
        'up_count': sum(1 for log in logs_data if log['status'] == 'UP'),
    }
    return render(request, 'monitor/logs.html', context)


@login_required
def profile(request):
    profile_obj = get_or_create_user_profile(request.user)

    if request.method == 'POST':
        action = request.POST.get('profile_action')

        if action == 'update_profile':
            profile_form = ProfileUpdateForm(
                request.POST,
                request.FILES,
                user=request.user,
                profile=profile_obj,
            )
            security_form = AccountSecurityForm(instance=profile_obj)
            password_form = AccountPasswordChangeForm(request.user)
            delete_account_form = DeleteAccountForm(user=request.user)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, 'Profile updated successfully.')
                return redirect('profile')
            messages.error(request, 'Profile update could not be saved. Review the highlighted fields.')
        elif action == 'update_security':
            profile_form = ProfileUpdateForm(user=request.user, profile=profile_obj)
            security_form = AccountSecurityForm(request.POST, instance=profile_obj)
            password_form = AccountPasswordChangeForm(request.user)
            delete_account_form = DeleteAccountForm(user=request.user)
            previous_two_factor = profile_obj.two_factor_enabled
            if security_form.is_valid():
                security_form.save()
                if not previous_two_factor and security_form.cleaned_data.get('two_factor_enabled'):
                    messages.warning(request, 'Two-factor is saved as a preference. Full 2FA verification is coming soon.')
                else:
                    messages.success(request, 'Security preferences updated successfully.')
                return redirect('profile')
            messages.error(request, 'Security preferences could not be saved. Review the highlighted fields.')
        elif action == 'change_password':
            profile_form = ProfileUpdateForm(user=request.user, profile=profile_obj)
            security_form = AccountSecurityForm(instance=profile_obj)
            password_form = AccountPasswordChangeForm(request.user, request.POST)
            delete_account_form = DeleteAccountForm(user=request.user)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Password changed successfully.')
                return redirect('profile')
            messages.error(request, 'Password change failed. Check your current password and confirm the new password fields.')
        elif action == 'delete_account':
            profile_form = ProfileUpdateForm(user=request.user, profile=profile_obj)
            security_form = AccountSecurityForm(instance=profile_obj)
            password_form = AccountPasswordChangeForm(request.user)
            delete_account_form = DeleteAccountForm(request.POST, user=request.user)
            if delete_account_form.is_valid():
                user = request.user
                auth_logout(request)
                user.delete()
                messages.success(request, 'Your account has been deleted.')
                return redirect('index')
            messages.error(request, 'Account deletion was not confirmed. Review the highlighted fields.')
        else:
            profile_form = ProfileUpdateForm(user=request.user, profile=profile_obj)
            security_form = AccountSecurityForm(instance=profile_obj)
            password_form = AccountPasswordChangeForm(request.user)
            delete_account_form = DeleteAccountForm(user=request.user)
    else:
        profile_form = ProfileUpdateForm(user=request.user, profile=profile_obj)
        security_form = AccountSecurityForm(instance=profile_obj)
        password_form = AccountPasswordChangeForm(request.user)
        delete_account_form = DeleteAccountForm(user=request.user)

    account_snapshot = get_user_account_snapshot(request.user)
    context = {
        'profile_form': profile_form,
        'security_form': security_form,
        'password_form': password_form,
        'delete_account_form': delete_account_form,
        'account_snapshot': account_snapshot,
    }
    return render(request, 'monitor/profile.html', context)


@login_required
def settings(request):
    profile_obj = get_or_create_user_profile(request.user)
    if request.method == 'POST':
        preferences_form = AccountPreferencesForm(request.POST, instance=profile_obj)
        if preferences_form.is_valid():
            previous_two_factor = profile_obj.two_factor_enabled
            preferences_form.save()
            if not previous_two_factor and preferences_form.cleaned_data.get('two_factor_enabled'):
                messages.warning(request, 'Two-factor is saved as a preference. Full 2FA verification is coming soon.')
            else:
                messages.success(request, 'Settings saved successfully.')
            return redirect('settings')
        messages.error(request, 'Settings could not be saved. Review the highlighted fields.')
    else:
        preferences_form = AccountPreferencesForm(instance=profile_obj)

    context = {
        'preferences_form': preferences_form,
        'account_snapshot': get_user_account_snapshot(request.user),
    }
    return render(request, 'monitor/settings.html', context)


@login_required
def notifications(request):
    cleanup_old_notifications(user=request.user)
    notifications_qs = get_notification_queryset(request.user)
    selected_severity = request.GET.get('severity', '').strip().lower()
    unread_only = request.GET.get('unread') == '1'
    selected_query = request.GET.get('q', '').strip()

    if selected_severity in {'critical', 'warning', 'success', 'info'}:
        notifications_qs = notifications_qs.filter(severity=selected_severity)
    if unread_only:
        notifications_qs = notifications_qs.filter(is_read=False)
    if selected_query:
        notifications_qs = notifications_qs.filter(
            Q(title__icontains=selected_query)
            | Q(message__icontains=selected_query)
            | Q(notification_type__icontains=selected_query)
            | Q(related_website__url__icontains=selected_query)
        )

    ordered_notifications = sorted(notifications_qs, key=notification_priority, reverse=True)
    paginator = Paginator(ordered_notifications, 20)
    page_obj = paginator.get_page(request.GET.get('page'))
    page_notifications = list(page_obj.object_list)
    for notification in page_notifications:
        notification.action_url = get_notification_destination(notification)
    notification_groups = _build_notification_groups(page_notifications)

    context = {
        'page_obj': page_obj,
        'notifications': page_notifications,
        'notification_groups': notification_groups,
        'selected_severity': selected_severity,
        'selected_query': selected_query,
        'unread_only': unread_only,
        'unread_count': get_unread_notification_count(request.user),
    }
    return render(request, 'monitor/notifications.html', context)


@login_required
@require_POST
def mark_notification_read(request, notification_id):
    notification = get_object_or_404(get_notification_queryset(request.user), id=notification_id)
    notification.is_read = True
    notification.save(update_fields=['is_read'])
    messages.success(request, 'Notification operationally acknowledged.')
    return redirect(request.POST.get('next') or 'notifications')


@login_required
@require_POST
def mark_all_notifications_read(request):
    get_notification_queryset(request.user).filter(is_read=False).update(is_read=True)
    messages.success(request, 'All visible notifications acknowledged.')
    return redirect(request.POST.get('next') or 'notifications')


@login_required
@require_POST
def delete_notification(request, notification_id):
    notification = get_object_or_404(get_notification_queryset(request.user), id=notification_id)
    notification.delete()
    messages.success(request, 'Notification deleted.')
    return redirect(request.POST.get('next') or 'notifications')


@login_required
def search(request):
    query = request.GET.get('q', '')
    results = build_global_search_results(request.user, query)
    if results['query']:
        remember_recent_search(request, results['query'])
    results['recent_searches'] = get_recent_searches(request)
    return render(request, 'monitor/search_results.html', results)


@login_required
def search_suggestions(request):
    query = request.GET.get('q', '')
    results = build_global_search_results(request.user, query, per_section=3)
    payload = []
    for website in results['websites']:
        payload.append({
            'group': 'Websites',
            'label': website.display_domain,
            'meta': website.url,
            'url': '/status/',
        })
    for incident in results['incidents']:
        payload.append({
            'group': 'Incidents',
            'label': incident.title,
            'meta': incident.website.display_domain,
            'url': '/incidents/',
        })
    for alert in results['alerts']:
        payload.append({
            'group': 'Alerts',
            'label': alert.alert_type,
            'meta': alert.website.display_domain,
            'url': '/alerts/',
        })
    for notification in results['notifications']:
        payload.append({
            'group': 'Notifications',
            'label': notification.title,
            'meta': notification.message[:80],
            'url': '/notifications/',
        })
    for log in results['logs']:
        payload.append({
            'group': 'Logs',
            'label': log.display_domain,
            'meta': log.status,
            'url': '/logs/',
        })
    return JsonResponse({
        'query': results['query'],
        'results': payload[:8],
        'recent_searches': get_recent_searches(request),
    })


def legal_page(request, slug):
    pages = {
        'privacy': {
            'title': 'Privacy Policy',
            'eyebrow': 'Privacy',
            'sections': [
                ('Data We Collect', 'SiteGuard stores the account, monitoring, incident, alert, and notification data required to operate your workspace.'),
                ('How We Use It', 'Data is used to authenticate users, run monitoring workflows, send alerts, and present analytics across the platform.'),
                ('Security', 'We keep access scoped to authenticated users and avoid exposing monitoring data outside the owning account.'),
            ],
        },
        'terms': {
            'title': 'Terms & Conditions',
            'eyebrow': 'Terms',
            'sections': [
                ('Service Usage', 'Use SiteGuard responsibly and do not attempt to abuse monitoring, search, notification, or account systems.'),
                ('Account Responsibility', 'Users are responsible for their credentials, configured endpoints, and any alerts or websites they manage.'),
                ('Availability', 'SiteGuard monitoring data is provided on a best-effort basis and may evolve as the platform grows.'),
            ],
        },
        'cookies': {
            'title': 'Cookie Policy',
            'eyebrow': 'Cookies',
            'sections': [
                ('Essential Cookies', 'Session cookies are used for login persistence and secure access to monitoring areas.'),
                ('Preference Storage', 'Recent searches and similar UX preferences may be stored in your session for a smoother experience.'),
                ('Control', 'You can clear browser cookies, but some authenticated features may require a fresh sign-in afterward.'),
            ],
        },
        'contact': {
            'title': 'Contact',
            'eyebrow': 'Contact',
            'sections': [
                ('Support', 'Reach the SiteGuard team for operational questions, account help, or product feedback.'),
                ('Email', django_settings.SUPPORT_EMAIL),
                ('Response', 'We aim to respond to platform questions as quickly as practical.'),
            ],
        },
        'security': {
            'title': 'Security Policy',
            'eyebrow': 'Security',
            'sections': [
                ('Monitoring Safety', 'SiteGuard validates domains, restricts unsafe utility targets, and keeps monitoring actions within authenticated ownership boundaries.'),
                ('Disclosure', 'If you discover a security issue, contact the team privately with clear reproduction details.'),
                ('Platform Direction', 'The account system is prepared for future OAuth and stronger authentication layers, including full 2FA flows.'),
            ],
        },
    }
    page = pages.get(slug)
    if page is None:
        return redirect('index')
    return render(request, 'legal_page.html', {'page': page})


@login_required
def alerts(request):
    cleanup_monitoring_state(user=request.user)
    alerts_qs = Alert.objects.filter(
        website__user=request.user
    ).select_related('website', 'incident').prefetch_related('incident__events').order_by('-created_at', '-id')
    websites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_logs = list(
        MonitorLog.objects.filter(website__user=request.user).select_related('website').order_by('-checked_at', '-id')
    )
    for alert in alerts_qs:
        set_display_domain(alert.website)
    for website in websites:
        set_display_domain(website)
    websites = _build_alert_preferences_snapshot(list(websites), list(alerts_qs), website_logs)

    active_alerts = alerts_qs.filter(
        is_read=False,
    ).exclude(
        alert_type=Alert.TYPE_RECOVERY,
    ).exclude(
        status=Alert.STATUS_FAILED,
    ).count()
    recovery_alerts = alerts_qs.filter(alert_type=Alert.TYPE_RECOVERY).count()
    failed_alerts = alerts_qs.filter(status=Alert.STATUS_FAILED).count()
    recent_alerts = alerts_qs[:20]
    average_response_impact = alerts_qs.exclude(response_time__isnull=True).aggregate(
        avg=Avg('response_time')
    )['avg'] or 0

    context = {
        'alerts': recent_alerts,
        'active_alerts': active_alerts,
        'recent_alerts_count': alerts_qs.count(),
        'recovery_alerts': recovery_alerts,
        'failed_alerts': failed_alerts,
        'average_response_impact': round(average_response_impact, 2),
        'websites': websites,
    }
    return render(request, 'monitor/alerts.html', context)


@login_required
@require_POST
def mark_alert_read(request, alert_id):
    alert = get_object_or_404(
        Alert,
        id=alert_id,
        website__user=request.user,
    )
    alert.is_read = True
    alert.read_at = timezone.now()
    alert.save(update_fields=['is_read', 'read_at'])
    messages.success(request, 'Alert operationally acknowledged.')
    return redirect('alerts')


@login_required
@require_POST
def retry_alert(request, alert_id):
    alert = get_object_or_404(
        Alert,
        id=alert_id,
        website__user=request.user,
    )
    if not alert.website.email_notifications or not alert.website.user.email:
        messages.error(request, 'Email notifications are disabled for this website.')
        return redirect('alerts')

    alert.status = Alert.STATUS_PENDING
    alert.sent_to = alert.website.user.email
    alert.save(update_fields=['status', 'sent_to'])

    sent = send_alert_email(alert, recovery_time=alert.incident.resolved_at if alert.incident else None)
    if sent:
        alert.status = Alert.STATUS_SENT
        alert.save(update_fields=['status'])
        messages.success(request, 'Alert delivery retried successfully.')
    else:
        alert.status = Alert.STATUS_FAILED
        alert.save(update_fields=['status'])
        messages.error(request, 'Alert retry failed.')

    return redirect('alerts')


@login_required
@require_POST
def update_website_alert_settings(request, website_id):
    website = get_object_or_404(
        Website,
        id=website_id,
        user=request.user,
    )
    website.alerts_enabled = request.POST.get('alerts_enabled') == 'on'
    website.email_notifications = request.POST.get('email_notifications') == 'on'
    try:
        threshold = int(request.POST.get('slow_alert_threshold', website.slow_alert_threshold))
    except (TypeError, ValueError):
        threshold = website.slow_alert_threshold
    website.slow_alert_threshold = max(threshold, 2000)
    website.save(update_fields=['alerts_enabled', 'email_notifications', 'slow_alert_threshold'])
    messages.success(request, f'Updated alert settings for {website.url}.')
    return redirect('alerts')


def _build_utility_result_meta(domain_result):
    state = 'failure'
    badge_class = 'badge-down'
    status_label = 'UNREACHABLE'

    if not domain_result:
        return {
            'state': state,
            'badge_class': badge_class,
            'status_label': status_label,
        }

    if domain_result.get('reachable'):
        latency = domain_result.get('latency', {})
        if latency.get('is_slow'):
            state = 'warning'
            badge_class = 'badge-slow'
            status_label = 'SLOW'
        else:
            state = 'success'
            badge_class = 'badge-up'
            status_label = 'REACHABLE'
    elif domain_result.get('error_message') == 'Request timed out.':
        state = 'warning'
        badge_class = 'badge-slow'
        status_label = 'TIMEOUT'
    elif domain_result.get('error_message'):
        status_label = 'UNREACHABLE' if domain_result.get('domain') else 'INVALID DOMAIN'

    return {
        'state': state,
        'badge_class': badge_class,
        'status_label': status_label,
    }


@login_required
def utilities(request):
    utility_context = {
        'encode_value': '',
        'encode_result': None,
        'decode_value': '',
        'decode_result': None,
        'domain_value': 'example.com',
        'domain_result': None,
        'utility_feedback': '',
        'utility_feedback_state': '',
    }

    if request.method == 'POST':
        action = request.POST.get('utility_action')

        if action == 'encode':
            encoded = safe_url_encode(request.POST.get('encode_input', ''))
            utility_context.update({
                'encode_value': encoded['value'],
                'encode_result': encoded,
            })
        elif action == 'decode':
            decoded = safe_url_decode(request.POST.get('decode_input', ''))
            utility_context.update({
                'decode_value': decoded['value'],
                'decode_result': decoded,
            })
        elif action == 'domain_check':
            domain_value = request.POST.get('domain_input', '')
            domain_result = analyze_domain(domain_value)
            domain_result.update(_build_utility_result_meta(domain_result))
            domain_result['already_monitored'] = (
                Website.objects.filter(
                    user=request.user,
                    url=Website.normalize_url(domain_result.get('domain', '')),
                ).exists()
                if domain_result.get('domain')
                else False
            )
            utility_context.update({
                'domain_value': domain_value,
                'domain_result': domain_result,
            })
        elif action == 'add_to_monitoring':
            raw_domain = request.POST.get('monitor_domain', '')
            try:
                normalized_domain = normalize_utility_domain(raw_domain)
                normalized_url = Website.normalize_url(normalized_domain)
                website, created = Website.objects.get_or_create(
                    user=request.user,
                    url=normalized_url,
                )
                utility_context['utility_feedback'] = (
                    'Domain added to monitoring.'
                    if created else
                    'Already monitored.'
                )
                utility_context['utility_feedback_state'] = 'success' if created else 'warning'
                domain_result = analyze_domain(normalized_domain)
                domain_result.update(_build_utility_result_meta(domain_result))
                domain_result['already_monitored'] = True
                utility_context.update({
                    'domain_value': normalized_domain,
                    'domain_result': domain_result,
                })
            except ValidationError as exc:
                utility_context['utility_feedback'] = exc.messages[0] if exc.messages else 'Enter a valid public domain.'
                utility_context['utility_feedback_state'] = 'failure'
            except Exception:
                logger.exception("Failed to add utility domain to monitoring.")
                utility_context['utility_feedback'] = 'Unable to add this domain to monitoring right now.'
                utility_context['utility_feedback_state'] = 'failure'

    return render(request, 'monitor/utilities.html', utility_context)


@login_required
def add_website(request):
    if request.method == 'POST':
        Website.cleanup_existing(user=request.user)
        raw_url = request.POST.get('url', '')

        if not raw_url.strip():
            messages.error(request, 'URL is required.')
            return redirect('dashboard')

        try:
            clean_url = Website.normalize_url(raw_url)
            Website.validate_normalized_url(clean_url)
        except ValidationError:
            messages.error(request, 'Invalid URL')
            return redirect('dashboard')

        if Website.objects.filter(user=request.user, url=clean_url).exists():
            messages.error(request, 'This website is already in your list.')
            return redirect('dashboard')

        try:
            website = Website.objects.create(user=request.user, url=clean_url)
        except ValidationError:
            messages.error(request, 'Invalid URL')
            return redirect('dashboard')
        except Exception:
            logger.exception("Failed to create monitored website.", extra={"url": clean_url, "user_id": request.user.id})
            messages.error(request, 'Website could not be added right now.')
            return redirect('dashboard')

        try:
            run_single_check(website)
        except Exception:
            logger.exception(
                "Initial monitoring check failed after website creation.",
                extra={"website_id": website.id, "user_id": request.user.id},
            )
            messages.warning(
                request,
                'Website added, but the initial monitoring check could not complete. The next monitoring run will retry it.',
            )
        else:
            messages.success(request, 'Website added and initial monitoring started immediately.')

        return redirect('dashboard')

    return redirect('dashboard')


@login_required
@require_POST
def delete_website(request, id):
    website = Website.objects.filter(id=id, user=request.user).first()

    if website is None:
        messages.error(request, 'Website not found.')
        return redirect('dashboard')

    website.delete()
    messages.success(request, 'Website deleted successfully!')
    return redirect('dashboard')
