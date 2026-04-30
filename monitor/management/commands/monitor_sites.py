"""
Django management command to monitor all websites.
Checks each website and logs the result to MonitorLog.
"""
import time
from django.core.management.base import BaseCommand
from django.utils import timezone
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
                
                checked_count += 1
                self.stdout.write(f'Checked: {website.url} | {status_text} | {round(response_time_ms, 2)}ms')
                
            except requests.exceptions.Timeout:
                # Timeout occurred
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | TIMEOUT | 0ms'))
                
            except requests.exceptions.RequestException as e:
                # Other request errors
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | 0ms'))
                
            except Exception as e:
                # Catch any other unexpected errors
                MonitorLog.objects.create(
                    website=website,
                    status=False,
                    response_time=0
                )
                error_count += 1
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | 0ms'))
        
        # Summary
        self.stdout.write(self.style.SUCCESS(f'\nMonitoring complete: {checked_count} checked, {error_count} errors'))
