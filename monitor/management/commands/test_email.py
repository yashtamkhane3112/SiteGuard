"""
Test email sending configuration.
Usage:
  python manage.py test_email your_test@gmail.com
  python manage.py test_email your_test@gmail.com --kind operational --site https://example.com
  python manage.py test_email your_test@gmail.com --kind password_reset
"""
from django.contrib.auth.models import User
from django.conf import settings
from django.core.management.base import BaseCommand
from django.utils import timezone

from monitor.emailing import build_password_reset_preview_url, get_email_base_url, get_email_diagnostics, send_siteguard_email
from monitor.forms import SiteGuardPasswordResetForm


class Command(BaseCommand):
    help = 'Test email sending configuration'

    def add_arguments(self, parser):
        parser.add_argument('recipient', type=str, help='Email address to send test to')
        parser.add_argument(
            '--kind',
            choices=['basic', 'operational', 'password_reset'],
            default='basic',
            help='Which email variant to send.',
        )
        parser.add_argument(
            '--site',
            default='https://example.com',
            help='Website URL to include in operational test emails.',
        )

    def handle(self, *args, **options):
        recipient = options['recipient']
        kind = options['kind']
        site = options['site']

        self.stdout.write('Testing email configuration...')
        self.stdout.write(f'Backend: {settings.EMAIL_BACKEND}')
        self.stdout.write(f'Email host configured: {bool(settings.EMAIL_HOST_USER)}')
        self.stdout.write(f'Canonical base URL: {getattr(settings, "CANONICAL_BASE_URL", "") or "(not set)"}')
        self.stdout.write(f'Resolved email base URL: {get_email_base_url() or "(not set)"}')
        self.stdout.write(f'Default from email: {settings.DEFAULT_FROM_EMAIL}')
        self.stdout.write(f'Server email: {settings.SERVER_EMAIL}')
        self.stdout.write(f'Email diagnostics: {get_email_diagnostics()}')

        if kind == 'password_reset':
            reset_user = User.objects.filter(email=recipient).order_by('date_joined', 'id').first()
            created = reset_user is None
            if reset_user is None:
                reset_user = User.objects.create(
                    username=f'smtp-reset-{timezone.now().strftime("%Y%m%d%H%M%S")}',
                    email=recipient,
                )
                reset_user.set_unusable_password()
                reset_user.save(update_fields=['password'])

            form = SiteGuardPasswordResetForm({'email': recipient})
            if not form.is_valid():
                self.stdout.write(self.style.ERROR('Password reset form validation failed.'))
                return

            preview_url = build_password_reset_preview_url(reset_user, get_email_base_url())
            self.stdout.write(f'Preview reset URL: {preview_url}')
            form.save(
                use_https=get_email_base_url().startswith("https://"),
                request=None,
                subject_template_name='registration/password_reset_subject.txt',
                email_template_name='registration/password_reset_email.txt',
            )
            if form._last_send_succeeded:
                self.stdout.write(self.style.SUCCESS(f'Password reset email sent to {recipient}'))
            else:
                self.stdout.write(self.style.ERROR('Password reset email failed. Check SMTP settings and logs.'))
            return

        if kind == 'operational':
            subject = f'Operational test: {site} email pipeline verification'
            text_body = (
                f'SiteGuard operational email test\n\n'
                f'Website: {site}\n'
                f'Alert Type: TEST\n'
                f'Status: Verification only\n'
                f'Sent at: {timezone.now()}\n'
                f'APP_BASE_URL: {getattr(settings, "CANONICAL_BASE_URL", "") or "(not set)"}\n'
            )
            html_body = (
                '<html><body style="font-family:Arial,sans-serif;">'
                '<h1 style="font-size:20px;">SiteGuard operational email test</h1>'
                f'<p><strong>Website:</strong> {site}</p>'
                '<p>This verifies SMTP delivery, HTML rendering, and sender identity.</p>'
                f'<p><strong>Sent at:</strong> {timezone.now()}</p>'
                '</body></html>'
            )
        else:
            subject = 'SiteGuard email test'
            text_body = (
                f'This is a test email from SiteGuard.\n\n'
                f'Sent at: {timezone.now()}\n'
                f'Config loaded successfully.'
            )
            html_body = None

        try:
            sent = send_siteguard_email(
                subject=subject,
                text_body=text_body,
                html_body=html_body,
                recipients=[recipient],
                from_email=settings.DEFAULT_FROM_EMAIL,
                log_context={'flow': 'management_test_email', 'kind': kind},
                raise_on_error=True,
            )
        except Exception as exc:
            self.stdout.write(self.style.ERROR(f'Email failed with SMTP error: {exc.__class__.__name__}: {exc}'))
            return
        if sent:
            self.stdout.write(self.style.SUCCESS(f'Test email sent to {recipient}'))
        else:
            self.stdout.write(self.style.ERROR('Email failed. Check SMTP settings and logs.'))
