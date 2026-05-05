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
    path('delete-website/<int:id>/', views.delete_website, name='delete_website'),
    path('status/', views.status, name='status'),
    path('reports/', views.reports, name='reports'),
    path('incidents/', views.incidents, name='incidents'),
    path('logs/', views.logs, name='logs'),
    path('profile/', views.profile, name='profile'),
    path('settings/', views.settings, name='settings'),
    path('alerts/', views.alerts, name='alerts'),
    path('utilities/', views.utilities, name='utilities'),
]

