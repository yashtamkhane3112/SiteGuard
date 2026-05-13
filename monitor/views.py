import logging
from datetime import timedelta
from collections import Counter, defaultdict
from hmac import compare_digest
from io import StringIO

from django.conf import settings as django_settings
from django.shortcuts import get_object_or_404, redirect, render
from django.http import Http404, HttpResponse, JsonResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.management import call_command
from django.core.paginator import Paginator
from django.db import connection
from django.db.utils import OperationalError, ProgrammingError
from django.db.models import Avg, Count, Sum
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_POST
from django.utils import timezone

from .forms import (
    AccountPasswordChangeForm,
    AccountPreferencesForm,
    AccountSecurityForm,
    DeleteAccountForm,
    LoginForm,
    ProfileUpdateForm,
    SignUpForm,
    UploadedLogForm,
)
from .error_analyzer import build_upload_analytics, get_error_diagnostics, process_uploaded_log
from .models import Alert, Incident, MonitorLog, ParsedError, UploadedLog, Website
from .utils import (
    analyze_domain,
    build_global_search_results,
    check_ssl_status,
    cleanup_monitoring_state,
    ensure_weekly_report_notification,
    get_favicon_url,
    get_latest_logs_by_website,
    get_notification_queryset,
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
            'class': 'bg-info',
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


# ✅ DASHBOARD (FULL FIXED)
@login_required
def dashboard(request):
    ensure_admin_user()
    Website.cleanup_existing(user=request.user)
    cleanup_monitoring_state(user=request.user)

    websites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_ids = websites.values_list('id', flat=True)

    all_logs = MonitorLog.objects.filter(
        website_id__in=website_ids
    ).select_related('website').order_by('-checked_at')

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

    total_logs = all_logs.count()
    up_logs = all_logs.filter(status=MonitorLog.STATUS_UP).count()

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
    sites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_ids = sites.values_list('id', flat=True)
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
    websites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_ids = websites.values_list('id', flat=True)
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
def check_now(request, website_id):
    website = get_object_or_404(
        Website,
        id=website_id,
        user=request.user,
    )

    run_single_check(website)
    messages.success(request, f"Checked {website.url}")
    return redirect('status')


@login_required
def reports(request):
    range_key = request.GET.get('range', '7d')
    if range_key not in {'24h', '7d', '30d'}:
        range_key = '7d'

    ensure_weekly_report_notification(request.user)
    context = build_reports_context(request.user, range_key)
    return render(request, 'monitor/reports.html', context)


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
        **summary,
    }
    return render(request, 'monitor/error_log_results.html', context)


@login_required
def incidents(request):
    cleanup_monitoring_state(user=request.user)
    incidents_qs = Incident.objects.filter(
        website__user=request.user
    ).select_related('website').prefetch_related('events').order_by('-started_at', '-created_at')
    for incident in incidents_qs:
        set_display_domain(incident.website)

    week_ago = timezone.now() - timedelta(days=7)
    active_incidents = incidents_qs.filter(is_resolved=False).count()
    resolved_this_week = incidents_qs.filter(
        is_resolved=True,
        resolved_at__gte=week_ago,
    ).count()

    resolved_incidents = [
        incident for incident in incidents_qs
        if incident.is_resolved and incident.resolved_at is not None
    ]
    average_resolution_time = "0m"
    if resolved_incidents:
        average_seconds = sum(
            max(int((incident.resolved_at - incident.started_at).total_seconds()), 0)
            for incident in resolved_incidents
        ) / len(resolved_incidents)
        average_resolution_time = format_duration_value(average_seconds)

    context = {
        'incidents': incidents_qs,
        'active_incidents': active_incidents,
        'resolved_this_week': resolved_this_week,
        'average_resolution_time': average_resolution_time,
    }
    return render(request, 'monitor/incidents.html', context)


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
    notifications_qs = get_notification_queryset(request.user)
    selected_severity = request.GET.get('severity', '').strip().lower()
    unread_only = request.GET.get('unread') == '1'

    if selected_severity in {'critical', 'warning', 'success', 'info'}:
        notifications_qs = notifications_qs.filter(severity=selected_severity)
    if unread_only:
        notifications_qs = notifications_qs.filter(is_read=False)

    paginator = Paginator(notifications_qs, 20)
    page_obj = paginator.get_page(request.GET.get('page'))

    context = {
        'page_obj': page_obj,
        'notifications': page_obj.object_list,
        'selected_severity': selected_severity,
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
    messages.success(request, 'Notification marked as read.')
    return redirect(request.POST.get('next') or 'notifications')


@login_required
@require_POST
def mark_all_notifications_read(request):
    get_notification_queryset(request.user).filter(is_read=False).update(is_read=True)
    messages.success(request, 'All notifications marked as read.')
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
                ('Email', 'webmaster@localhost'),
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
    for alert in alerts_qs:
        set_display_domain(alert.website)
    for website in websites:
        set_display_domain(website)

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
    messages.success(request, 'Alert marked as read.')
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

    try:
        send_alert_email(alert, recovery_time=alert.incident.resolved_at if alert.incident else None)
        alert.status = Alert.STATUS_SENT
        alert.save(update_fields=['status'])
        messages.success(request, 'Alert delivery retried successfully.')
    except Exception:
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
            except Exception:
                utility_context['utility_feedback'] = 'Unable to add this domain to monitoring.'
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
        except Exception:
            messages.error(request, 'Invalid URL')
            return redirect('dashboard')

        if Website.objects.filter(user=request.user, url=clean_url).exists():
            messages.error(request, 'This website is already in your list.')
            return redirect('dashboard')

        try:
            website = Website.objects.create(user=request.user, url=clean_url)
            run_single_check(website)
            messages.success(request, 'Website added and initial monitoring started immediately.')
        except Exception:
            messages.error(request, 'Invalid URL')
            return redirect('dashboard')

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
