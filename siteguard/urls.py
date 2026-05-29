"""
URL configuration for siteguard project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.http import Http404
from django.urls import include, path, re_path
from django.views.generic.base import RedirectView
from django.views.static import serve

handler404 = 'monitor.views.custom_404'
handler500 = 'monitor.views.custom_500'


def serve_media(request, path):
    media_root = getattr(settings, "MEDIA_ROOT", None)
    if not media_root:
        raise Http404("Media storage is not served from the local filesystem.")
    return serve(request, path, document_root=media_root)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('favicon.ico', RedirectView.as_view(url=f"{settings.STATIC_URL}icons/favicon.ico?v=v3.0.2-favicon-svg-master", permanent=True)),
    path('', include('monitor.urls')),
]

if settings.MEDIA_URL and getattr(settings, "MEDIA_ROOT", None):
    media_prefix = settings.MEDIA_URL.lstrip("/")
    urlpatterns += [
        re_path(
            rf"^{media_prefix}(?P<path>.*)$",
            serve_media,
        ),
    ]
