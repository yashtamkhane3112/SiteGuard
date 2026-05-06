from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.utils import timezone
import re
from urllib.parse import urlsplit


class Website(models.Model):
    """Model representing a website to be monitored."""
    SIMPLE_DOMAIN_ALIASES = {
        'amazon',
        'apple',
        'facebook',
        'github',
        'gmail',
        'google',
        'instagram',
        'linkedin',
        'microsoft',
        'netflix',
        'outlook',
        'reddit',
        'twitter',
        'yahoo',
        'youtube',
    }

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='websites')
    url = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    @classmethod
    def normalize_url(cls, url):
        cleaned_url = (url or '').strip().lower()
        if '.' not in cleaned_url and cleaned_url.isalpha() and cleaned_url in cls.SIMPLE_DOMAIN_ALIASES:
            cleaned_url = f'{cleaned_url}.com'
        if cleaned_url and not cleaned_url.startswith(('http://', 'https://')):
            cleaned_url = f'https://{cleaned_url}'
        return cleaned_url

    @classmethod
    def validate_normalized_url(cls, url):
        raw_url = (url or '').strip().lower()
        if any(char.isspace() for char in raw_url):
            raise ValidationError('Invalid URL')

        if '.' not in raw_url.removeprefix('http://').removeprefix('https://'):
            if not raw_url.isalpha() or raw_url not in cls.SIMPLE_DOMAIN_ALIASES:
                raise ValidationError('Invalid URL')

        validator = URLValidator(schemes=['http', 'https'])
        validator(url)

        parsed = urlsplit(url)
        if (
            not parsed.netloc
            or '.' not in parsed.netloc
            or not re.fullmatch(r'[a-z0-9.-]+', parsed.netloc)
        ):
            raise ValidationError('Invalid URL')

    @classmethod
    def cleanup_existing(cls, user=None):
        websites = cls.objects.all()
        if user is not None:
            websites = websites.filter(user=user)

        seen = set()
        for website in websites.order_by('user_id', 'created_at', 'id'):
            raw_url = website.url or ''
            if ' ' in raw_url:
                website.delete()
                continue

            try:
                normalized_url = cls.normalize_url(raw_url)
                cls.validate_normalized_url(normalized_url)
            except ValidationError:
                website.delete()
                continue

            key = (website.user_id, normalized_url)
            if key in seen:
                website.delete()
                continue

            if website.url != normalized_url:
                website.url = normalized_url
                website.save(update_fields=['url'])
            seen.add(key)

    def clean(self):
        self.url = self.normalize_url(self.url)
        self.validate_normalized_url(self.url)

    def save(self, *args, **kwargs):
        self.full_clean()
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.url} (owned by {self.user.username})"

    class Meta:
        ordering = ['-created_at']
        unique_together = ['user', 'url']


class MonitorLog(models.Model):
    """Model representing a monitoring check result for a website."""
    STATUS_UP = 'UP'
    STATUS_DOWN = 'DOWN'
    STATUS_SLOW = 'SLOW'
    STATUS_CHOICES = [
        (STATUS_UP, 'UP'),
        (STATUS_DOWN, 'DOWN'),
        (STATUS_SLOW, 'SLOW'),
    ]

    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='monitor_logs')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=STATUS_UP)
    response_time = models.FloatField()  # in milliseconds
    checked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.website.url} - {self.status} ({self.response_time}ms)"

    class Meta:
        ordering = ['-checked_at']


class Incident(models.Model):
    STATUS_DOWN = 'DOWN'
    STATUS_SLOW = 'SLOW'
    STATUS_RESOLVED = 'RESOLVED'
    STATUS_CHOICES = [
        (STATUS_DOWN, 'DOWN'),
        (STATUS_SLOW, 'SLOW'),
        (STATUS_RESOLVED, 'RESOLVED'),
    ]

    TYPE_OUTAGE = 'outage'
    TYPE_PERFORMANCE = 'performance'
    TYPE_SSL = 'ssl'
    TYPE_CHOICES = [
        (TYPE_OUTAGE, 'Outage'),
        (TYPE_PERFORMANCE, 'Performance'),
        (TYPE_SSL, 'SSL'),
    ]

    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='incidents')
    title = models.CharField(max_length=255)
    incident_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES)
    started_at = models.DateTimeField()
    resolved_at = models.DateTimeField(null=True, blank=True)
    is_resolved = models.BooleanField(default=False)
    latest_response_time = models.FloatField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-started_at', '-created_at']

    def __str__(self):
        return f"{self.website.url} - {self.title} ({self.status})"

    @property
    def filter_key(self):
        if self.is_resolved:
            return 'resolved'
        if self.status == self.STATUS_DOWN:
            return 'critical'
        if self.status == self.STATUS_SLOW:
            return 'warning'
        return 'all'

    @property
    def badge_class(self):
        if self.is_resolved:
            return 'badge-up'
        if self.status == self.STATUS_DOWN:
            return 'badge-down'
        if self.status == self.STATUS_SLOW:
            return 'badge-slow'
        return 'badge-up'

    @property
    def status_label(self):
        if self.is_resolved:
            return 'RESOLVED'
        return self.status

    @property
    def icon_name(self):
        if self.is_resolved:
            return 'check-circle'
        if self.status == self.STATUS_DOWN:
            return 'zap'
        if self.status == self.STATUS_SLOW:
            return 'alert-triangle'
        return 'shield-alert'

    @property
    def icon_bg_class(self):
        if self.is_resolved:
            return 'bg-good-light'
        if self.status == self.STATUS_DOWN:
            return 'bg-critical-light'
        if self.status == self.STATUS_SLOW:
            return 'bg-warning-light'
        return 'bg-panel-light'

    @property
    def icon_text_class(self):
        if self.is_resolved:
            return 'text-good'
        if self.status == self.STATUS_DOWN:
            return 'text-critical'
        if self.status == self.STATUS_SLOW:
            return 'text-warning'
        return 'text-white'

    @property
    def incident_code(self):
        return f"INC-{self.pk:03d}" if self.pk else "INC-000"

    @property
    def duration_display(self):
        end_time = self.resolved_at or timezone.now()
        total_seconds = max(int((end_time - self.started_at).total_seconds()), 0)
        hours, remainder = divmod(total_seconds, 3600)
        minutes, _ = divmod(remainder, 60)
        duration = f"{hours}h {minutes}m" if hours else f"{minutes}m"
        if self.is_resolved:
            return duration
        return 'Ongoing' if total_seconds < 60 else duration


class IncidentEvent(models.Model):
    TYPE_DETECTED = 'detected'
    TYPE_INVESTIGATING = 'investigating'
    TYPE_IDENTIFIED = 'identified'
    TYPE_MONITORING = 'monitoring'
    TYPE_RESOLVED = 'resolved'
    TYPE_CHOICES = [
        (TYPE_DETECTED, 'Detected'),
        (TYPE_INVESTIGATING, 'Investigating'),
        (TYPE_IDENTIFIED, 'Identified'),
        (TYPE_MONITORING, 'Monitoring'),
        (TYPE_RESOLVED, 'Resolved'),
    ]

    incident = models.ForeignKey(Incident, on_delete=models.CASCADE, related_name='events')
    event_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']

    def __str__(self):
        return f"{self.incident} - {self.event_type}"

    @property
    def label(self):
        return self.get_event_type_display()

    @property
    def icon_name(self):
        icon_map = {
            self.TYPE_DETECTED: 'wifi-off',
            self.TYPE_INVESTIGATING: 'clock',
            self.TYPE_IDENTIFIED: 'alert-triangle',
            self.TYPE_MONITORING: 'activity',
            self.TYPE_RESOLVED: 'check-circle',
        }
        return icon_map.get(self.event_type, 'clock')

    @property
    def text_class(self):
        text_map = {
            self.TYPE_DETECTED: 'text-critical',
            self.TYPE_INVESTIGATING: 'text-warning',
            self.TYPE_IDENTIFIED: 'text-white',
            self.TYPE_MONITORING: 'text-info',
            self.TYPE_RESOLVED: 'text-good',
        }
        return text_map.get(self.event_type, 'text-white')
