from django.db import models
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
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
    website = models.ForeignKey(Website, on_delete=models.CASCADE, related_name='monitor_logs')
    status = models.BooleanField(default=True)  # True=UP, False=DOWN
    response_time = models.FloatField()  # in milliseconds
    checked_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        status_text = "UP" if self.status else "DOWN"
        return f"{self.website.url} - {status_text} ({self.response_time}ms)"

    class Meta:
        ordering = ['-checked_at']
