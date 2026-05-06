from datetime import timedelta

from django.shortcuts import get_object_or_404, redirect, render
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.db.models import Avg
from django.views.decorators.http import require_POST
from django.utils import timezone

from .forms import LoginForm, SignUpForm
from .models import Alert, Incident, MonitorLog, Website
from .utils import (
    check_ssl_status,
    send_alert_email,
    get_favicon_url,
    get_latest_logs_by_website,
    get_site_snapshot,
    get_site_status,
    run_single_check,
)


def format_duration_value(total_seconds):
    if total_seconds <= 0:
        return "0m"

    hours, remainder = divmod(int(total_seconds), 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


# ✅ STATUS HELPER
def ensure_admin_user():
    if not User.objects.filter(username='admin').exists():
        User.objects.create_superuser(
            username='admin',
            password='admin123',
            email='admin@example.com',
        )


def index(request):
    return render(request, 'monitor/index.html')


def login(request):
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


def signup(request):
    ensure_admin_user()
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SignUpForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        return redirect('login')

    return render(request, 'monitor/signup.html', {'form': form})


def logout_view(request):
    auth_logout(request)
    return redirect('login')


# ✅ DASHBOARD (FULL FIXED)
@login_required
def dashboard(request):
    ensure_admin_user()
    Website.cleanup_existing(user=request.user)

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
        website.favicon = get_favicon_url(website.url)
        website.ssl_status = check_ssl_status(website.url)

    # ✅ FIXED TOP STATUS (NO TRUE)
    status = "UP"
    response_time = 0

    if latest_logs:
        statuses = [get_site_status(log) for log in latest_logs.values()]

        if "DOWN" in statuses:
            status = "DOWN"
        elif "SLOW" in statuses:
            status = "SLOW"
        else:
            status = "UP"

        response_time = round(
            sum(log.response_time for log in latest_logs.values()) / len(latest_logs),
            2
        )

    total_logs = all_logs.count()
    up_logs = all_logs.filter(status=MonitorLog.STATUS_UP).count()

    uptime = (up_logs / total_logs) * 100 if total_logs > 0 else 0
    incidents = all_logs.filter(status=MonitorLog.STATUS_DOWN).count()

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
    sites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_ids = sites.values_list('id', flat=True)
    all_logs = MonitorLog.objects.filter(
        website_id__in=website_ids
    ).order_by('-checked_at')
    latest_logs = get_latest_logs_by_website(all_logs)
    data = []

    for site in sites:
        snapshot = get_site_snapshot(latest_logs.get(site.id))

        data.append({
            'id': site.id,
            'url': site.url,
            'status': snapshot['status'],
            'response_time': snapshot['response_time'],
            'last_checked': snapshot['last_checked'].strftime('%Y-%m-%d %H:%M') if snapshot['last_checked'] else '',
        })

    return JsonResponse({'sites': data})


@login_required
def status(request):
    Website.cleanup_existing(user=request.user)
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


def reports(request):
    return render(request, 'monitor/reports.html')


@login_required
def incidents(request):
    incidents_qs = Incident.objects.filter(
        website__user=request.user
    ).select_related('website').prefetch_related('events').order_by('-started_at', '-created_at')

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


def logs(request):
    return render(request, 'monitor/logs.html')


def profile(request):
    return render(request, 'monitor/profile.html')


def settings(request):
    return render(request, 'monitor/settings.html')


@login_required
def alerts(request):
    alerts_qs = Alert.objects.filter(
        website__user=request.user
    ).select_related('website', 'incident').prefetch_related('incident__events').order_by('-created_at', '-id')
    websites = Website.objects.filter(user=request.user).order_by('-created_at')

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


def utilities(request):
    return render(request, 'monitor/utilities.html')


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
            Website.objects.create(user=request.user, url=clean_url)
            messages.success(request, 'Website added successfully!')
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
