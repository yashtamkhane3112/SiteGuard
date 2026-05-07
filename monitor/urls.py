from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('add-website/', views.add_website, name='add_website'),
    path('check-now/<int:website_id>/', views.check_now, name='check_now'),
    path('delete-website/<int:id>/', views.delete_website, name='delete_website'),
    path('status/', views.status, name='status'),
    path('reports/', views.reports, name='reports'),
    path('incidents/', views.incidents, name='incidents'),
    path('logs/', views.logs, name='logs'),
    path('profile/', views.profile, name='profile'),
    path('settings/', views.settings, name='settings'),
    path('alerts/', views.alerts, name='alerts'),
    path('alerts/<int:alert_id>/mark-read/', views.mark_alert_read, name='mark_alert_read'),
    path('alerts/<int:alert_id>/retry/', views.retry_alert, name='retry_alert'),
    path('alerts/preferences/<int:website_id>/', views.update_website_alert_settings, name='update_website_alert_settings'),
    path('notifications/', views.notifications, name='notifications'),
    path('notifications/<int:notification_id>/mark-read/', views.mark_notification_read, name='mark_notification_read'),
    path('notifications/<int:notification_id>/delete/', views.delete_notification, name='delete_notification'),
    path('notifications/mark-all-read/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('search/', views.search, name='search'),
    path('search/suggestions/', views.search_suggestions, name='search_suggestions'),
    path('utilities/', views.utilities, name='utilities'),
    path('legal/<slug:slug>/', views.legal_page, name='legal_page'),
]

