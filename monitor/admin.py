from django.contrib import admin
from .models import Website, MonitorLog


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
