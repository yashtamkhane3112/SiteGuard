from .utils import (
    build_notification_activity_center,
    get_recent_notifications,
    get_recent_searches,
    get_unread_notification_count,
    get_user_account_snapshot,
)


def global_ui_context(request):
    if not getattr(request, 'user', None) or not request.user.is_authenticated:
        return {
            'global_notifications': [],
            'global_unread_notifications_count': 0,
            'global_recent_searches': get_recent_searches(request),
            'account_snapshot': None,
        }

    activity_center = build_notification_activity_center(request.user)
    return {
        'global_notifications': get_recent_notifications(request.user),
        'global_notification_activity': activity_center,
        'global_unread_notifications_count': get_unread_notification_count(request.user),
        'global_recent_searches': get_recent_searches(request),
        'account_snapshot': get_user_account_snapshot(request.user),
    }
