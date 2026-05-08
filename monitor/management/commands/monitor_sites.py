"""
Django management command to monitor all websites once.
Uses the shared monitoring workflow for incidents and alerts.
Suitable for cron-based scheduling on Render.
"""

from django.core.management.base import BaseCommand

from monitor.models import Website
from monitor.utils import run_single_check


class Command(BaseCommand):
    help = 'Monitor all websites once and log the results'

    def add_arguments(self, parser):
        parser.add_argument(
            '--timeout',
            type=int,
            default=5,
            help='Timeout for each request in seconds (default: 5)'
        )

    def handle(self, *args, **options):
        timeout = options['timeout']
        self.stdout.write('Starting monitoring cycle...')
        websites = Website.objects.all().select_related('user')

        if not websites.exists():
            self.stdout.write(self.style.WARNING('No websites to monitor'))
            return

        self.stdout.write(self.style.SUCCESS(f'Starting to monitor {websites.count()} website(s)...'))

        checked_count = 0
        error_count = 0

        for website in websites:
            try:
                log, _response = run_single_check(website, timeout=timeout)
                checked_count += 1
                self.stdout.write(
                    f'Checked: {website.url} | {log.status} | {round(log.response_time, 2)}ms'
                )
            except Exception as exc:
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | {exc}'))

        self.stdout.write(
            self.style.SUCCESS(
                f'Monitoring complete: {checked_count} checked, {error_count} errors'
            )
        )
