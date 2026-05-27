"""
Django management command to monitor all websites once.
Uses the shared monitoring workflow for incidents and alerts.
Suitable for cron-based scheduling on Render.
"""

import logging

from django.core.management.base import BaseCommand

from monitor.models import Website
from monitor.utils import prune_expired_monitor_logs, run_single_check


logger = logging.getLogger(__name__)


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
        logger.info(
            "Scheduled monitoring cycle started.",
            extra={
                "monitoring_context": {
                    "stage": "scheduler_start",
                    "timeout": timeout,
                    "website_count": websites.count(),
                }
            },
        )

        checked_count = 0
        error_count = 0

        if not websites.exists():
            pruned_logs = prune_expired_monitor_logs()
            self.stdout.write(self.style.WARNING('No websites to monitor'))
            self.stdout.write(self.style.SUCCESS(f'Pruned {pruned_logs} expired monitoring log(s).'))
            return

        self.stdout.write(self.style.SUCCESS(f'Starting to monitor {websites.count()} website(s)...'))

        for website in websites:
            try:
                log, _response = run_single_check(website, timeout=timeout)
                checked_count += 1
                logger.info(
                    "Scheduled monitoring check completed.",
                    extra={
                        "monitoring_context": {
                            "stage": "scheduler_check_complete",
                            "website_id": website.id,
                            "log_id": log.id if log else None,
                            "status": getattr(log, "status", ""),
                            "response_time": getattr(log, "response_time", None),
                        }
                    },
                )
                self.stdout.write(
                    f'Checked: {website.url} | {log.status} | {round(log.response_time, 2)}ms'
                )
            except Exception as exc:
                error_count += 1
                logger.exception(
                    "Scheduled monitoring check failed.",
                    extra={
                        "monitoring_context": {
                            "stage": "scheduler_check_failed",
                            "website_id": website.id,
                            "timeout": timeout,
                        }
                    },
                )
                self.stdout.write(self.style.ERROR(f'Checked: {website.url} | ERROR | {exc}'))

        pruned_logs = prune_expired_monitor_logs()
        logger.info(
            "Scheduled monitoring cycle finished.",
            extra={
                "monitoring_context": {
                    "stage": "scheduler_complete",
                    "checked_count": checked_count,
                    "error_count": error_count,
                    "pruned_log_count": pruned_logs,
                }
            },
        )
        self.stdout.write(
            self.style.SUCCESS(
                f'Monitoring complete: {checked_count} checked, {error_count} errors, {pruned_logs} log(s) pruned'
            )
        )
