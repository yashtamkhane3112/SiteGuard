# Project Structure

## Root

- `manage.py`: Django management entrypoint
- `requirements.txt`: dependencies
- `render.yaml`: Render blueprint
- `Procfile`: process declaration
- `start.sh`: production startup script
- `.env.example`: sample environment file

## Project Package

- `siteguard/settings/base.py`: shared settings
- `siteguard/settings/dev.py`: development settings
- `siteguard/settings/prod.py`: production settings
- `siteguard/urls.py`: root routes
- `siteguard/wsgi.py`: WSGI app
- `siteguard/asgi.py`: ASGI app

## Main App

- `monitor/models.py`: monitoring, incidents, alerts, notifications, profiles
- `monitor/views.py`: UI, auth, cron trigger, health check
- `monitor/forms.py`: forms
- `monitor/utils.py`: monitoring logic and helpers
- `monitor/admin.py`: admin registrations
- `monitor/migrations/`: schema history
- `monitor/management/commands/`: operational commands

## Templates and Static

- `templates/monitor/`: application pages
- `templates/errors/`: error pages
- `static/css/style.css`
- `static/js/script.js`

## Runtime Directories

- `media/`
- `staticfiles/`
- `data/`

These are runtime outputs and are ignored in git.
