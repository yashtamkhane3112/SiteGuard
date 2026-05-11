from django.contrib import admin
from .models import Alert, Incident, IncidentEvent, MonitorLog, Notification, UserProfile, Website


@admin.register(Website)
class WebsiteAdmin(admin.ModelAdmin):
    list_display = ['url', 'user', 'created_at']
    list_filter = ['created_at']
    search_fields = ['url', 'user__username']
    raw_id_fields = ['user']


@admin.register(MonitorLog)
class MonitorLogAdmin(admin.ModelAdmin):
    list_display = ['website', 'status', 'response_time', 'checked_at']
    list_filter = ['status', 'checked_at']
    search_fields = ['website__url']
    raw_id_fields = ['website']


@admin.register(Incident)
class IncidentAdmin(admin.ModelAdmin):
    list_display = ['title', 'website', 'incident_type', 'status', 'started_at', 'is_resolved']
    list_filter = ['incident_type', 'status', 'is_resolved']
    search_fields = ['title', 'website__url', 'website__user__username']
    raw_id_fields = ['website']


@admin.register(IncidentEvent)
class IncidentEventAdmin(admin.ModelAdmin):
    list_display = ['incident', 'event_type', 'created_at']
    list_filter = ['event_type', 'created_at']
    search_fields = ['incident__title', 'incident__website__url', 'message']
    raw_id_fields = ['incident']


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = ['website', 'alert_type', 'status', 'sent_to', 'created_at', 'is_read']
    list_filter = ['alert_type', 'status', 'is_read']
    search_fields = ['website__url', 'sent_to', 'message']
    raw_id_fields = ['website', 'incident']


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ['user', 'title', 'notification_type', 'severity', 'is_read', 'created_at']
    list_filter = ['notification_type', 'severity', 'is_read']
    search_fields = ['user__username', 'title', 'message']
    raw_id_fields = ['user', 'related_incident', 'related_website']


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'timezone', 'email_alerts_enabled', 'monitoring_frequency', 'updated_at']
    list_filter = ['timezone', 'monitoring_frequency', 'email_alerts_enabled']
    search_fields = ['user__username', 'user__email']
    raw_id_fields = ['user']
