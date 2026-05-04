"""
Django management command to monitor all websites.
Checks each website and logs the result to MonitorLog.
🚨 SENDS EMAIL ALERTS when site goes DOWN (UP→DOWN transition only)
"""
import time
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import requests
from monitor.models import Website, MonitorLog


class Command(BaseCommand):
    help = 'Monitor all websites and log results'

    def add_arguments(self, parser):
        parser.add_argument(
            '--timeout',
            type=int,
            default=5,
            help='Timeout for each request in seconds (default: 5)'
        )

    def handle(self, *args, **options):
        timeout = options['timeout']
        
        # Get all websites
        websites = Website.objects.all()
        
        if not websites:
            self.stdout.write(self.style.WARNING('No websites to monitor'))
            return
        
        self.stdout.write(self.style.SUCCESS(f'Starting to monitor {websites.count()} website(s)...'))
        
        checked_count = 0
        error_count = 0
        
        for website in websites:
            try:
                # Measure response time
                start_time = time.time()
                
                response = requests.get(website.url, timeout=timeout)
                
                end_time = time.time()
                response_time_ms = (end_time - start_time) * 1000
                
                # Get LAST MonitorLog BEFORE creating new one (for alert logic)
                last_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
                
                # Determine status
                if response.status_code == 200:
                    status = True
                    status_text = 'UP'
                else:
                    status = False
                    status_text = 'DOWN'
                
                # Create MonitorLog entry
                MonitorLog.objects.create(
                    website=website,
                    status=status,
                    response_time=round(response_time_ms, 2)
                )
                
                # 🚨 EMAIL ALERT: Only send when UP→DOWN transition AND user has email
                if not status and last_log and last_log.status and website.user.email:
                    try:
                        subject = "🚨 Site Down Alert"
                        message = f"""🚨 SITE DOWN ALERT

Website: {website.url}
Status: DOWN
Timestamp: {timezone.now()}
Response Time: {round(response_time_ms, 2)}ms

This site just transitioned from UP → DOWN!"""
                        
                        send_mail(
                            subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [website.user.email],
                            fail_silently=True,
                        )
                        self.stdout.write(self.style.WARNING(f'🚨 EMAIL DOWN ALERT SENT → {website.user.email}'))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f'❌ Email failed {website.url}: {str(e)}'))
                
                checked_count += 1
                self.stdout.write(f'Checked: {website.url} | {status_text} | {round(response_time_ms, 2)}ms')
                
            except requests.exceptions.Timeout:
# Timeout occurred
                last_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
                self.stdout.write(f'DEBUG: Previous: {last_log.status if last_log else "None"} → Current: False')
                
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                
                # 🚨 EMAIL ALERT: Only UP→DOWN transition
                if last_log and last_log.status and website.user.email:

                    try:
                        subject = "🚨 Site Down Alert (Timeout)"
                        message = f"""🚨 SITE DOWN ALERT - TIMEOUT

Website: {website.url}
Status: DOWN (Timeout)
Timestamp: {timezone.now()}

Site timed out! (Previous status: UP)"""
                        send_mail(
                            subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [website.user.email],
                            fail_silently=True,
                        )
                        self.stdout.write(self.style.WARNING(f'🚨 TIMEOUT ALERT SENT → {website.user.email}'))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f'❌ Email timeout {website.url}: {str(e)}'))
                        
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | TIMEOUT | 0ms'))
                
            except requests.exceptions.RequestException as e:
# Other request errors
                last_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
                self.stdout.write(f'DEBUG: Previous: {last_log.status if last_log else "None"} → Current: False')
                
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                
                # 🚨 EMAIL ALERT: Only UP→DOWN transition
                if last_log and last_log.status and website.user.email:

                    try:
                        subject = "🚨 Site Down Alert (Request Error)"
                        message = f"""🚨 SITE DOWN ALERT - REQUEST ERROR

Website: {website.url}
Status: DOWN (Connection Error)
Timestamp: {timezone.now()}
Error: {str(e)}

Site became unreachable! (Previous: UP)"""
                        send_mail(
                            subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [website.user.email],
                            fail_silently=True,
                        )
                        self.stdout.write(self.style.WARNING(f'🚨 REQUEST ERROR ALERT → {website.user.email}'))
                    except Exception as email_e:
                        self.stdout.write(self.style.ERROR(f'❌ Email request-err {website.url}: {str(email_e)}'))
                        
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | 0ms'))
                
            except Exception as e:
# Catch any other unexpected errors
                last_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
                self.stdout.write(f'DEBUG: Previous: {last_log.status if last_log else "None"} → Current: False')
                
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                
                # 🚨 EMAIL ALERT: Only UP→DOWN transition
                if last_log and last_log.status and website.user.email:

                    try:
                        subject = "🚨 Site Down Alert (Unexpected Error)"
                        message = f"""🚨 SITE DOWN ALERT - UNEXPECTED ERROR

Website: {website.url}
Status: DOWN
Timestamp: {timezone.now()}
Error: {str(e)}

Unexpected monitoring error! (Previous: UP)"""
                        send_mail(
                            subject,
                            message,
                            settings.EMAIL_HOST_USER,
                            [website.user.email],
                            fail_silently=True,
                        )
                        self.stdout.write(self.style.WARNING(f'🚨 UNEXPECTED ERROR ALERT → {website.user.email}'))
                    except Exception as email_e:
                        self.stdout.write(self.style.ERROR(f'❌ Email unexpected {website.url}: {str(email_e)}'))
                        
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | 0ms'))
        
        # Summary
        self.stdout.write(self.style.SUCCESS(f'\nMonitoring complete: {checked_count} checked, {error_count} errors'))
