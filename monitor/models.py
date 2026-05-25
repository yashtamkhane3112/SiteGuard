import os
import re
from urllib.parse import urlsplit

from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.utils import validate_file_name
from django.core.validators import URLValidator
from django.db import models
from django.db.models import Q
from django.db.models.signals import post_save
from django.dispatch import receiver
from django.utils import timezone

from .storage import AnalyzerUploadStorage, get_uploaded_log_storage as resolve_uploaded_log_storage


def uploaded_log_file_path(instance, filename):
    safe_name = validate_file_name(os.path.basename(filename or 'upload.log'))
    timestamp = timezone.now().strftime('%Y%m%d%H%M%S')
    return f'error_logs/user_{instance.user_id}/{timestamp}_{safe_name}'


def get_uploaded_log_storage():
    return resolve_uploaded_log_storage()


STATUS_TONE_HEALTHY = 'healthy'
STATUS_TONE_CRITICAL = 'critical'
STATUS_TONE_HIGH = 'high'
STATUS_TONE_WARNING = 'warning'
STATUS_TONE_INFO = 'info'
STATUS_TONE_ACTIVE = 'active'
STATUS_TONE_RECOVERED = 'recovered'
STATUS_TONE_FAILED = 'failed'
STATUS_TONE_NEUTRAL = 'neutral'


def tone_to_badge_class(tone):
    return {
        STATUS_TONE_HEALTHY: 'badge-up',
        STATUS_TONE_RECOVERED: 'badge-recovery',
        STATUS_TONE_CRITICAL: 'badge-down',
        STATUS_TONE_FAILED: 'badge-down',
        STATUS_TONE_HIGH: 'badge-slow',
        STATUS_TONE_WARNING: 'badge-purple',
        STATUS_TONE_INFO: 'badge-info',
        STATUS_TONE_ACTIVE: 'badge-active',
        STATUS_TONE_NEUTRAL: 'badge-purple',
    }.get(tone, 'badge-purple')


def tone_to_icon_bg_class(tone):
    return {
        STATUS_TONE_HEALTHY: 'bg-good-light',
        STATUS_TONE_RECOVERED: 'bg-recovery-light',
        STATUS_TONE_CRITICAL: 'bg-critical-light',
        STATUS_TONE_FAILED: 'bg-critical-light',
        STATUS_TONE_HIGH: 'bg-warning-light',
        STATUS_TONE_WARNING: 'bg-medium-light',
        STATUS_TONE_INFO: 'bg-info-light',
        STATUS_TONE_ACTIVE: 'bg-active-light',
        STATUS_TONE_NEUTRAL: 'bg-panel-light',
    }.get(tone, 'bg-panel-light')


def tone_to_icon_text_class(tone):
    return {
        STATUS_TONE_HEALTHY: 'text-good',
        STATUS_TONE_RECOVERED: 'text-recovery',
        STATUS_TONE_CRITICAL: 'text-critical',
        STATUS_TONE_FAILED: 'text-critical',
        STATUS_TONE_HIGH: 'text-warning',
        STATUS_TONE_WARNING: 'text-purple',
        STATUS_TONE_INFO: 'text-info-tone',
        STATUS_TONE_ACTIVE: 'text-active',
        STATUS_TONE_NEUTRAL: 'text-white',
    }.get(tone, 'text-white')


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
    alerts_enabled = models.BooleanField(default=True)
    email_notifications = models.BooleanField(default=True)
    slow_alert_threshold = models.PositiveIntegerField(default=2000)
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


class UserProfile(models.Model):
    FREQ_1_MIN = '1'
    FREQ_5_MIN = '5'
    FREQ_15_MIN = '15'
    FREQ_30_MIN = '30'
    MONITORING_FREQUENCY_CHOICES = [
        (FREQ_1_MIN, '1 min'),
        (FREQ_5_MIN, '5 min'),
        (FREQ_15_MIN, '15 min'),
        (FREQ_30_MIN, '30 min'),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    avatar = models.FileField(upload_to='avatars/', max_length=500, blank=True, null=True)
    timezone = models.CharField(max_length=64, default='UTC')
    email_alerts_enabled = models.BooleanField(default=True)
    ssl_alerts_enabled = models.BooleanField(default=True)
    incident_alerts_enabled = models.BooleanField(default=True)
    marketing_emails_enabled = models.BooleanField(default=False)
    monitoring_frequency = models.CharField(
        max_length=4,
        choices=MONITORING_FREQUENCY_CHOICES,
        default=FREQ_5_MIN,
    )
    two_factor_enabled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['user__username']

    def __str__(self):
        return f"Profile for {self.user.username}"


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
        indexes = [
            models.Index(fields=['website', '-checked_at'], name='monitor_mon_website_8e0d66_idx'),
        ]


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
        indexes = [
            models.Index(fields=['website', 'is_resolved', 'incident_type', '-started_at'], name='monitor_inc_website_cfef0e_idx'),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['website', 'incident_type'],
                condition=Q(is_resolved=False),
                name='unique_active_incident_per_type',
            ),
        ]

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
            return tone_to_badge_class(STATUS_TONE_RECOVERED)
        if self.status == self.STATUS_DOWN:
            return tone_to_badge_class(STATUS_TONE_CRITICAL)
        if self.status == self.STATUS_SLOW:
            return tone_to_badge_class(STATUS_TONE_HIGH)
        return tone_to_badge_class(STATUS_TONE_ACTIVE)

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
            return tone_to_icon_bg_class(STATUS_TONE_RECOVERED)
        if self.status == self.STATUS_DOWN:
            return tone_to_icon_bg_class(STATUS_TONE_CRITICAL)
        if self.status == self.STATUS_SLOW:
            return tone_to_icon_bg_class(STATUS_TONE_HIGH)
        return tone_to_icon_bg_class(STATUS_TONE_ACTIVE)

    @property
    def icon_text_class(self):
        if self.is_resolved:
            return tone_to_icon_text_class(STATUS_TONE_RECOVERED)
        if self.status == self.STATUS_DOWN:
            return tone_to_icon_text_class(STATUS_TONE_CRITICAL)
        if self.status == self.STATUS_SLOW:
            return tone_to_icon_text_class(STATUS_TONE_HIGH)
        return tone_to_icon_text_class(STATUS_TONE_ACTIVE)

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
            self.TYPE_MONITORING: 'text-active',
            self.TYPE_RESOLVED: 'text-good',
        }
        return text_map.get(self.event_type, 'text-white')


class Alert(models.Model):
    TYPE_DOWN = 'DOWN'
    TYPE_SLOW = 'SLOW'
    TYPE_RECOVERY = 'RECOVERY'
    TYPE_SSL = 'SSL'
    TYPE_CHOICES = [
        (TYPE_DOWN, 'DOWN'),
        (TYPE_SLOW, 'SLOW'),
        (TYPE_RECOVERY, 'RECOVERY'),
        (TYPE_SSL, 'SSL'),
    ]

    STATUS_SENT = 'SENT'
    STATUS_FAILED = 'FAILED'
    STATUS_PENDING = 'PENDING'
    STATUS_CHOICES = [
        (STATUS_SENT, 'SENT'),
        (STATUS_FAILED, 'FAILED'),
        (STATUS_PENDING, 'PENDING'),
    ]

    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='alerts')
    incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        related_name='alerts',
        null=True,
        blank=True,
    )
    alert_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
    message = models.TextField()
    sent_to = models.EmailField(blank=True)
    response_time = models.FloatField(null=True, blank=True)
    is_read = models.BooleanField(default=False)
    read_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['website', 'alert_type', 'status', '-created_at'], name='monitor_ale_website_1a96eb_idx'),
        ]

    def __str__(self):
        return f"{self.website.url} - {self.alert_type} ({self.status})"

    @property
    def filter_key(self):
        if self.status == self.STATUS_FAILED:
            return 'failed'
        if self.alert_type == self.TYPE_DOWN:
            return 'critical'
        if self.alert_type in {self.TYPE_SLOW, self.TYPE_SSL}:
            return 'warning'
        if self.alert_type == self.TYPE_RECOVERY:
            return 'recovery'
        return 'all'

    @property
    def badge_class(self):
        if self.status == self.STATUS_FAILED:
            return tone_to_badge_class(STATUS_TONE_FAILED)
        if self.alert_type == self.TYPE_DOWN:
            return tone_to_badge_class(STATUS_TONE_CRITICAL)
        if self.alert_type == self.TYPE_SLOW:
            return tone_to_badge_class(STATUS_TONE_HIGH)
        if self.alert_type == self.TYPE_SSL:
            return tone_to_badge_class(STATUS_TONE_WARNING)
        return tone_to_badge_class(STATUS_TONE_RECOVERED)

    @property
    def status_label(self):
        if self.status == self.STATUS_FAILED:
            return 'FAILED'
        return self.alert_type

    @property
    def icon_name(self):
        if self.status == self.STATUS_FAILED:
            return 'alert-octagon'
        icon_map = {
            self.TYPE_DOWN: 'wifi-off',
            self.TYPE_SLOW: 'clock-3',
            self.TYPE_RECOVERY: 'check-circle',
            self.TYPE_SSL: 'shield-alert',
        }
        return icon_map.get(self.alert_type, 'bell')

    @property
    def icon_bg_class(self):
        if self.status == self.STATUS_FAILED:
            return tone_to_icon_bg_class(STATUS_TONE_FAILED)
        if self.alert_type == self.TYPE_DOWN:
            return tone_to_icon_bg_class(STATUS_TONE_CRITICAL)
        if self.alert_type == self.TYPE_SLOW:
            return tone_to_icon_bg_class(STATUS_TONE_HIGH)
        if self.alert_type == self.TYPE_SSL:
            return tone_to_icon_bg_class(STATUS_TONE_WARNING)
        return tone_to_icon_bg_class(STATUS_TONE_RECOVERED)

    @property
    def icon_text_class(self):
        if self.status == self.STATUS_FAILED:
            return tone_to_icon_text_class(STATUS_TONE_FAILED)
        if self.alert_type == self.TYPE_DOWN:
            return tone_to_icon_text_class(STATUS_TONE_CRITICAL)
        if self.alert_type == self.TYPE_SLOW:
            return tone_to_icon_text_class(STATUS_TONE_HIGH)
        if self.alert_type == self.TYPE_SSL:
            return tone_to_icon_text_class(STATUS_TONE_WARNING)
        return tone_to_icon_text_class(STATUS_TONE_RECOVERED)


class Notification(models.Model):
    TYPE_OUTAGE = 'outage'
    TYPE_RECOVERY = 'recovery'
    TYPE_SSL = 'ssl'
    TYPE_REPORT = 'report'
    TYPE_WARNING = 'warning'
    TYPE_INFO = 'info'
    TYPE_CHOICES = [
        (TYPE_OUTAGE, 'Outage'),
        (TYPE_RECOVERY, 'Recovery'),
        (TYPE_SSL, 'SSL'),
        (TYPE_REPORT, 'Report'),
        (TYPE_WARNING, 'Warning'),
        (TYPE_INFO, 'Info'),
    ]

    SEVERITY_CRITICAL = 'critical'
    SEVERITY_WARNING = 'warning'
    SEVERITY_SUCCESS = 'success'
    SEVERITY_INFO = 'info'
    SEVERITY_CHOICES = [
        (SEVERITY_CRITICAL, 'Critical'),
        (SEVERITY_WARNING, 'Warning'),
        (SEVERITY_SUCCESS, 'Success'),
        (SEVERITY_INFO, 'Info'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    message = models.TextField()
    notification_type = models.CharField(max_length=20, choices=TYPE_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default=SEVERITY_INFO)
    related_incident = models.ForeignKey(
        Incident,
        on_delete=models.SET_NULL,
        related_name='notifications',
        null=True,
        blank=True,
    )
    related_website = models.ForeignKey(
        Website,
        on_delete=models.SET_NULL,
        related_name='notifications',
        null=True,
        blank=True,
    )
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at', '-id']
        indexes = [
            models.Index(fields=['user', 'is_read', '-created_at']),
            models.Index(fields=['user', 'notification_type', 'severity']),
        ]

    def __str__(self):
        return f"{self.user.username} - {self.title}"

    @property
    def badge_class(self):
        return {
            self.SEVERITY_CRITICAL: tone_to_badge_class(STATUS_TONE_CRITICAL),
            self.SEVERITY_WARNING: tone_to_badge_class(STATUS_TONE_WARNING),
            self.SEVERITY_SUCCESS: tone_to_badge_class(STATUS_TONE_RECOVERED),
            self.SEVERITY_INFO: tone_to_badge_class(STATUS_TONE_INFO),
        }.get(self.severity, tone_to_badge_class(STATUS_TONE_INFO))

    @property
    def icon_name(self):
        return {
            self.TYPE_OUTAGE: 'wifi-off',
            self.TYPE_RECOVERY: 'check-circle',
            self.TYPE_SSL: 'shield-alert',
            self.TYPE_REPORT: 'file-text',
            self.TYPE_WARNING: 'clock-3',
            self.TYPE_INFO: 'bell',
        }.get(self.notification_type, 'bell')

    @property
    def icon_bg_class(self):
        return {
            self.SEVERITY_CRITICAL: tone_to_icon_bg_class(STATUS_TONE_CRITICAL),
            self.SEVERITY_WARNING: tone_to_icon_bg_class(STATUS_TONE_WARNING),
            self.SEVERITY_SUCCESS: tone_to_icon_bg_class(STATUS_TONE_RECOVERED),
            self.SEVERITY_INFO: tone_to_icon_bg_class(STATUS_TONE_INFO),
        }.get(self.severity, tone_to_icon_bg_class(STATUS_TONE_INFO))

    @property
    def icon_text_class(self):
        return {
            self.SEVERITY_CRITICAL: tone_to_icon_text_class(STATUS_TONE_CRITICAL),
            self.SEVERITY_WARNING: tone_to_icon_text_class(STATUS_TONE_WARNING),
            self.SEVERITY_SUCCESS: tone_to_icon_text_class(STATUS_TONE_RECOVERED),
            self.SEVERITY_INFO: tone_to_icon_text_class(STATUS_TONE_INFO),
        }.get(self.severity, tone_to_icon_text_class(STATUS_TONE_INFO))


class UploadedLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='uploaded_logs')
    filename = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    file = models.FileField(upload_to=uploaded_log_file_path, storage=AnalyzerUploadStorage())
    processed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-uploaded_at', '-id']

    def __str__(self):
        return f"{self.filename} ({self.user.username})"


class ParsedError(models.Model):
    CATEGORY_DATABASE = 'database'
    CATEGORY_AUTHENTICATION = 'authentication'
    CATEGORY_TIMEOUT = 'timeout'
    CATEGORY_HTTP = 'http'
    CATEGORY_NETWORK = 'network'
    CATEGORY_DJANGO = 'django'
    CATEGORY_FRONTEND = 'frontend'
    CATEGORY_SECURITY = 'security'
    CATEGORY_UNKNOWN = 'unknown'
    CATEGORY_CHOICES = [
        (CATEGORY_DATABASE, 'Database'),
        (CATEGORY_AUTHENTICATION, 'Authentication'),
        (CATEGORY_TIMEOUT, 'Timeout'),
        (CATEGORY_HTTP, 'HTTP'),
        (CATEGORY_NETWORK, 'Network'),
        (CATEGORY_DJANGO, 'Django'),
        (CATEGORY_FRONTEND, 'Frontend'),
        (CATEGORY_SECURITY, 'Security'),
        (CATEGORY_UNKNOWN, 'Unknown'),
    ]

    SEVERITY_CRITICAL = 'critical'
    SEVERITY_HIGH = 'high'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_LOW = 'low'
    SEVERITY_CHOICES = [
        (SEVERITY_CRITICAL, 'Critical'),
        (SEVERITY_HIGH, 'High'),
        (SEVERITY_MEDIUM, 'Medium'),
        (SEVERITY_LOW, 'Low'),
    ]

    uploaded_log = models.ForeignKey(UploadedLog, on_delete=models.CASCADE, related_name='parsed_errors')
    error_type = models.CharField(max_length=120)
    raw_line = models.TextField()
    count = models.PositiveIntegerField(default=1)
    first_seen_line = models.PositiveIntegerField()
    last_seen_line = models.PositiveIntegerField(default=1)
    category = models.CharField(max_length=32, choices=CATEGORY_CHOICES, default=CATEGORY_UNKNOWN)
    severity = models.CharField(max_length=16, choices=SEVERITY_CHOICES, default=SEVERITY_LOW)

    class Meta:
        ordering = ['-count', 'first_seen_line', 'id']

    def __str__(self):
        return f"{self.error_type} x{self.count}"

    @property
    def line_range_display(self):
        if self.last_seen_line and self.last_seen_line != self.first_seen_line:
            return f"Lines {self.first_seen_line}-{self.last_seen_line}"
        return f"Line {self.first_seen_line}"

    @property
    def category_label(self):
        return self.get_category_display()

    @property
    def severity_label(self):
        return self.get_severity_display()

    @property
    def category_badge_class(self):
        return {
            self.CATEGORY_DATABASE: 'badge-purple',
            self.CATEGORY_AUTHENTICATION: 'badge-slow',
            self.CATEGORY_TIMEOUT: 'badge-slow',
            self.CATEGORY_HTTP: 'badge-info',
            self.CATEGORY_NETWORK: 'badge-down',
            self.CATEGORY_DJANGO: 'badge-purple',
            self.CATEGORY_FRONTEND: 'badge-info',
            self.CATEGORY_SECURITY: 'badge-down',
            self.CATEGORY_UNKNOWN: 'badge-info',
        }.get(self.category, 'badge-info')

    @property
    def severity_badge_class(self):
        return {
            self.SEVERITY_CRITICAL: 'badge-down',
            self.SEVERITY_HIGH: 'badge-slow',
            self.SEVERITY_MEDIUM: 'badge-purple',
            self.SEVERITY_LOW: 'badge-info',
        }.get(self.severity, 'badge-info')


class AIAnalysisCache(models.Model):
    SCOPE_REPORT = 'report'
    SCOPE_ERROR_UPLOAD = 'error_upload'
    SCOPE_INCIDENT = 'incident'
    SCOPE_CHOICES = [
        (SCOPE_REPORT, 'Report'),
        (SCOPE_ERROR_UPLOAD, 'Error Upload'),
        (SCOPE_INCIDENT, 'Incident'),
    ]

    STATUS_READY = 'ready'
    STATUS_FAILED = 'failed'
    STATUS_DISABLED = 'disabled'
    STATUS_CHOICES = [
        (STATUS_READY, 'Ready'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_DISABLED, 'Disabled'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ai_analysis_cache')
    scope = models.CharField(max_length=32, choices=SCOPE_CHOICES)
    scope_key = models.CharField(max_length=160)
    input_hash = models.CharField(max_length=64)
    status = models.CharField(max_length=16, choices=STATUS_CHOICES, default=STATUS_READY)
    provider = models.CharField(max_length=64, blank=True)
    model_name = models.CharField(max_length=120, blank=True)
    content = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)
    generated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at', '-id']
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'scope', 'scope_key'],
                name='unique_ai_analysis_cache_scope',
            ),
        ]
        indexes = [
            models.Index(fields=['user', 'scope', 'scope_key'], name='monitor_ai_user_scope_idx'),
            models.Index(fields=['status', '-updated_at'], name='monitor_ai_status_idx'),
        ]

    def __str__(self):
        return f"{self.user.username} {self.scope}:{self.scope_key} ({self.status})"


@receiver(post_save, sender=User)
def ensure_user_profile(sender, instance, created, **kwargs):
    if created:
        UserProfile.objects.get_or_create(user=instance)
        return

    UserProfile.objects.get_or_create(user=instance)
