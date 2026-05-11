"""
WSGI config for siteguard project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

default_settings = 'siteguard.settings.dev'
if os.environ.get('RENDER') or os.environ.get('RENDER_EXTERNAL_HOSTNAME'):
    default_settings = 'siteguard.settings.prod'
os.environ.setdefault('DJANGO_SETTINGS_MODULE', default_settings)

application = get_wsgi_application()
