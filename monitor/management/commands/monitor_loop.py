"""
Django management command to run continuous monitoring loop.
Checks websites every 5 minutes indefinitely.
"""
import time
from django.core.management.base import BaseCommand
from django.core.management import call_command


class Command(BaseCommand):
    help = 'Run continuous monitoring loop - checks websites every 5 minutes'

    def add_arguments(self, parser):
        parser.add_argument(
            '--interval',
            type=int,
            default=300,
            help='Interval in seconds between checks (default: 300 = 5 minutes)'
        )

    def handle(self, *args, **options):
        interval = options['interval']
        
        self.stdout.write(self.style.SUCCESS(
            '\n========================================\n'
            '  SiteGuard Continuous Monitoring\n'
            '========================================\n'
        ))
        self.stdout.write(f'Starting continuous monitoring loop...')
        self.stdout.write(f'Interval: {interval} seconds ({interval // 60} minutes)')
        self.stdout.write('Press Ctrl+C to stop\n')
        
        cycle = 1
        
        try:
            while True:
                self.stdout.write(self.style.SUCCESS(f'\n--- Cycle {cycle} ---'))
                self.stdout.write('Running monitoring cycle...')
                
                # Call the monitor_sites command
                call_command('monitor_sites')
                
                self.stdout.write(f'Sleeping for {interval} seconds ({interval // 60} minutes)...')
                cycle += 1
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING(
                '\n\nMonitoring loop stopped by user (Ctrl+C)'
            ))
            self.stdout.write(self.style.SUCCESS(
                'Continuous monitoring ended.\n'
            ))
            return
        
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'\nError in monitoring loop: {e}'))
            self.stdout.write('Restarting loop in 60 seconds...')
            time.sleep(60)
            
            # Retry once after error
            try:
                while True:
                    self.stdout.write(self.style.SUCCESS(f'\n--- Cycle {cycle} ---'))
                    self.stdout.write('Running monitoring cycle...')
                    call_command('monitor_sites')
                    self.stdout.write(f'Sleeping for {interval} seconds...')
                    cycle += 1
                    time.sleep(interval)
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nMonitoring loop stopped.'))
                return
