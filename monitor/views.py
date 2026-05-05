from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib import messages

from .forms import LoginForm, SignUpForm
from .models import Website, MonitorLog


def index(request):
    return render(request, 'monitor/index.html')


def login(request):
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
    if request.user.is_authenticated:
        return redirect('dashboard')

    form = SignUpForm(request.POST or None)
    if request.method == 'POST' and form.is_valid():
        form.save()
        return redirect('login')

    return render(request, 'monitor/signup.html', {'form': form})


@login_required
def dashboard(request):
    """Dashboard view showing user's websites and recent activity."""
    websites = Website.objects.filter(user=request.user).order_by('-created_at')
    # Fetch latest MonitorLog entries for user's websites (last 10)
    website_ids = websites.values_list('id', flat=True)
    logs = MonitorLog.objects.filter(website_id__in=website_ids).select_related('website').order_by('-checked_at')[:10]
    return render(request, 'monitor/dashboard.html', {'websites': websites, 'logs': logs})


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
        url = request.POST.get('url', '').strip()
        
        # Validate URL is not empty
        if not url:
            messages.error(request, 'URL is required.')
            return redirect('dashboard')
        
        # Normalize URL - add https:// if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Check for duplicate URL for the same user
        if Website.objects.filter(user=request.user, url=url).exists():
            messages.error(request, 'This website is already in your list.')
            return redirect('dashboard')
        
        try:
            # Create new Website object
            Website.objects.create(
                user=request.user,
                url=url
            )
            messages.success(request, 'Website added successfully!')
        except Exception as e:
            messages.error(request, f'Invalid URL format.')
            return redirect('dashboard')
        
        return redirect('dashboard')
    
    # GET request - redirect to dashboard
    return redirect('dashboard')

