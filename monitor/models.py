from django.db import models
from django.contrib.auth.models import User


class Website(models.Model):
    """Model representing a website to be monitored."""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='websites')
    url = models.URLField(max_length=500)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.url} (owned by {self.user.username})"

    class Meta:
        ordering = ['-created_at']


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
