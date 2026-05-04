"""
Test email sending configuration.
Usage: python manage.py test_email your_test@gmail.com
"""
from django.core.management.base import BaseCommand
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone


class Command(BaseCommand):
    help = 'Test email sending configuration'

    def add_arguments(self, parser):
        parser.add_argument('recipient', type=str, help='Email address to send test to')

    def handle(self, *args, **options):
        recipient = options['recipient']
        
        self.stdout.write('Testing email configuration...')
        self.stdout.write(f'Host user: {settings.EMAIL_HOST_USER}')
        self.stdout.write(f'Backend: {settings.EMAIL_BACKEND}')
        
        try:
            send_mail(
                'SiteGuard Email Test ✅',
                f'This is a test email from SiteGuard.\n\n'
                f'Sent at: {timezone.now()}\n'
                f'Config loaded successfully!',
                settings.EMAIL_HOST_USER,
                [recipient],
                fail_silently=False,
            )
            self.stdout.write(self.style.SUCCESS(f'✅ Test email sent to {recipient}'))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'❌ Email failed: {str(e)}'))

