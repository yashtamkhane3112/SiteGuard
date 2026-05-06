"""
Django management command to monitor all websites.
Checks each website and logs the result to MonitorLog.
Sends email alerts when a site transitions from UP to DOWN.
"""
import time

import requests
from django.conf import settings
from django.core.mail import send_mail
from django.core.management.base import BaseCommand
from django.utils import timezone

from monitor.models import MonitorLog, Website
from monitor.utils import run_single_check


class Command(BaseCommand):
    help = 'Monitor all websites and log results'

    def add_arguments(self, parser):
        parser.add_argument(
            '--timeout',
            type=int,
            default=5,
            help='Timeout for each request in seconds (default: 5)'
        )

    def send_down_alert(self, website, previous_log, response_time_ms, status_label, details=''):
        if not previous_log or previous_log.status == MonitorLog.STATUS_DOWN or not website.user.email:
            return False

        message = (
            'SiteGuard detected a website outage.\n\n'
            f'Website: {website.url}\n'
            f'Status: {status_label}\n'
            f'Timestamp: {timezone.now()}\n'
            f'Response Time: {round(response_time_ms, 2)}ms\n'
        )
        if details:
            message += f'Details: {details}\n'
        message += '\nThis alert was sent because the site transitioned from UP to DOWN.'

        send_mail(
            f'SiteGuard Alert: {website.url} is DOWN',
            message,
            settings.DEFAULT_FROM_EMAIL,
            [website.user.email],
            fail_silently=False,
        )
        return True

    def handle(self, *args, **options):
        timeout = options['timeout']
        try:
            while True:
                self.stdout.write('Starting monitoring cycle...')
                websites = Website.objects.all()

                if not websites:
                    self.stdout.write(self.style.WARNING('No websites to monitor'))
                    self.stdout.write('Cycle complete. Waiting 60 seconds...')
                    time.sleep(60)
                    continue

                self.stdout.write(self.style.SUCCESS(f'Starting to monitor {websites.count()} website(s)...'))

                checked_count = 0
                error_count = 0

                for website in websites:
                    previous_log = MonitorLog.objects.filter(website=website).order_by('-checked_at').first()
                    try:
                        log, response = run_single_check(website, timeout=timeout)
                        status = log.status
                        response_time_ms = log.response_time
                        status_text = status

                        if status == MonitorLog.STATUS_DOWN:
                            try:
                                if self.send_down_alert(
                                    website,
                                    previous_log,
                                    response_time_ms,
                                    'DOWN',
                                    f'HTTP {response.status_code}' if response is not None else 'Request failed',
                                ):
                                    self.stdout.write(self.style.WARNING(f'DOWN alert sent to {website.user.email}'))
                            except Exception as e:
                                self.stdout.write(self.style.ERROR(f'Email failed {website.url}: {str(e)}'))

                        checked_count += 1
                        self.stdout.write(f'Checked: {website.url} | {status_text} | {round(response_time_ms, 2)}ms')

                    except Exception as e:
                        try:
                            if self.send_down_alert(website, previous_log, 0, 'DOWN', str(e)):
                                self.stdout.write(self.style.WARNING(f'Request error alert sent to {website.user.email}'))
                        except Exception as email_e:
                            self.stdout.write(self.style.ERROR(f'Email request error {website.url}: {str(email_e)}'))

                        error_count += 1
                        self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | 0ms'))

                self.stdout.write(self.style.SUCCESS(f'\nMonitoring complete: {checked_count} checked, {error_count} errors'))
                self.stdout.write('Cycle complete. Waiting 60 seconds...')
                time.sleep(60)
        except KeyboardInterrupt:
            self.stdout.write('Monitoring stopped by user')
