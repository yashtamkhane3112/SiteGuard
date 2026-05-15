from django.urls import path
from django.contrib.auth import views as auth_views
from . import views
from .forms import SiteGuardPasswordResetForm, SiteGuardSetPasswordForm

urlpatterns = [
    path('', views.index, name='index'),
    path('health/', views.health_check, name='health_check'),
    path('internal/run-monitoring/<str:token>/', views.internal_monitoring_trigger, name='internal_monitoring_trigger'),
    path('login/', views.login, name='login'),
    path('signup/', views.signup, name='signup'),
    path('logout/', views.logout_view, name='logout'),
    path(
        'password-reset/',
        auth_views.PasswordResetView.as_view(
            template_name='registration/password_reset_form.html',
            email_template_name='registration/password_reset_email.html',
            subject_template_name='registration/password_reset_subject.txt',
            form_class=SiteGuardPasswordResetForm,
        ),
        name='password_reset',
    ),
    path(
        'password-reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='registration/password_reset_done.html',
        ),
        name='password_reset_done',
    ),
    path(
        'reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='registration/password_reset_confirm.html',
            form_class=SiteGuardSetPasswordForm,
        ),
        name='password_reset_confirm',
    ),
    path(
        'reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='registration/password_reset_complete.html',
        ),
        name='password_reset_complete',
    ),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('dashboard-data/', views.dashboard_data, name='dashboard_data'),
    path('add-website/', views.add_website, name='add_website'),
    path('check-now/<int:website_id>/', views.check_now, name='check_now'),
    path('delete-website/<int:id>/', views.delete_website, name='delete_website'),
    path('status/', views.status, name='status'),
    path('reports/', views.reports, name='reports'),
    path('reports/weekly/', views.weekly_reports, name='weekly_reports'),
    path('reports/weekly/<slug:week_key>/', views.weekly_reports, name='weekly_report_detail'),
    path('error-analyzer/', views.error_log_upload, name='error_log_upload'),
    path('error-analyzer/<int:upload_id>/', views.error_log_results, name='error_log_results'),
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

