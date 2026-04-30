from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django import forms

from .models import Website


def index(request):
    return render(request, 'monitor/index.html')


def login(request):
    return render(request, 'monitor/login.html')


def signup(request):
    return render(request, 'monitor/signup.html')


def dashboard(request):
    return render(request, 'monitor/dashboard.html')


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

