"""
Django management command to monitor all websites.
Checks each website and logs the result to MonitorLog.
Uses the shared monitoring workflow for incidents and alerts.
"""
import time

from django.core.management.base import BaseCommand

from monitor.models import Website
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
                    try:
                        log, _response = run_single_check(website, timeout=timeout)
                        status = log.status
                        response_time_ms = log.response_time
                        status_text = status

                        checked_count += 1
                        self.stdout.write(f'Checked: {website.url} | {status_text} | {round(response_time_ms, 2)}ms')

                    except Exception as e:
                        error_count += 1
                        self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | {str(e)}'))

                self.stdout.write(self.style.SUCCESS(f'\nMonitoring complete: {checked_count} checked, {error_count} errors'))
                self.stdout.write('Cycle complete. Waiting 60 seconds...')
                time.sleep(60)
        except KeyboardInterrupt:
            self.stdout.write('Monitoring stopped by user')
