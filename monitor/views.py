from django.shortcuts import render, redirect
from django.http import JsonResponse
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.views.decorators.http import require_POST

from .forms import LoginForm, SignUpForm
from .models import Website, MonitorLog


def get_site_status(log):
    return log.status if log else MonitorLog.STATUS_DOWN


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


@login_required
def dashboard(request):
    """Dashboard view showing user's websites and recent activity."""
    ensure_admin_user()
    Website.cleanup_existing(user=request.user)
    websites = Website.objects.filter(user=request.user).order_by('-created_at')
    website_ids = websites.values_list('id', flat=True)
    all_logs = MonitorLog.objects.filter(website_id__in=website_ids).select_related('website').order_by('-checked_at')
    latest_log = all_logs.first()
    logs = all_logs[:20]
    sites = []

    for website in websites:
        site_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
        sites.append({
            'id': website.id,
            'url': website.url,
            'created_at': website.created_at,
            'status': get_site_status(site_log),
            'response_time': round(site_log.response_time, 2) if site_log else 0,
            'last_checked': site_log.checked_at if site_log else None,
        })

    status = MonitorLog.STATUS_UP
    response_time = 0
    if latest_log is not None:
        status = latest_log.status
        response_time = round(latest_log.response_time, 2)

    total_logs = all_logs.count()
    up_logs = all_logs.filter(status=MonitorLog.STATUS_UP).count()
    uptime = (up_logs / total_logs) * 100 if total_logs > 0 else 0
    incidents = all_logs.filter(status=MonitorLog.STATUS_DOWN).count()
    has_slow = any(site['status'] == MonitorLog.STATUS_SLOW for site in sites)

    context = {
        'sites': sites,
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
    sites = Website.objects.filter(user=request.user).order_by('-created_at')
    data = []

    for site in sites:
        latest = MonitorLog.objects.filter(website=site).order_by('-checked_at').first()
        data.append({
            'id': site.id,
            'url': site.url,
            'status': get_site_status(latest),
            'response_time': round(latest.response_time, 2) if latest else 0,
            'last_checked': latest.checked_at.strftime('%Y-%m-%d %H:%M') if latest else '',
        })

    return JsonResponse({'sites': data})


def status(request):
    return render(request, 'monitor/status.html')


def reports(request):
    return render(request, 'monitor/reports.html')


def incidents(request):
    return render(request, 'monitor/incidents.html')


def logs(request):
    return render(request, 'monitor/logs.html')


def profile(request):
    return render(request, 'monitor/profile.html')


def settings(request):
    return render(request, 'monitor/settings.html')


def alerts(request):
    return render(request, 'monitor/alerts.html')


def utilities(request):
    return render(request, 'monitor/utilities.html')


@login_required
def add_website(request):
    """Handle adding a new website from frontend UI."""
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
            Website.objects.create(
                user=request.user,
                url=clean_url
            )
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

