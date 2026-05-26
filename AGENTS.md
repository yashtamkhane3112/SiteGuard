# Repository Guidelines

## Project Structure
`siteguard/` contains Django 5 settings, validation helpers, and ASGI/WSGI entrypoints. `monitor/` is the main application for monitoring, incidents, alerts, notifications, email transport, AI analysis, Cloudinary storage integration, and management commands. Templates live in `templates/`, source assets in `static/`, and regression coverage is concentrated in `monitor/tests.py`.

## Development Commands
Use Python 3.12 and the repo-local virtual environment.

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py runserver
.\.venv\Scripts\python.exe manage.py monitor_sites
.\.venv\Scripts\python.exe manage.py test_email you@example.com --kind operational --site https://example.com
```

SQLite is local-only. Production uses Render, Neon PostgreSQL, DB-backed sessions, Cloudinary media plus raw analyzer uploads, Brevo transactional email, and optional Gemini operational intelligence.

## Testing and Deployment Validation
Run the full suite before shipping changes to monitoring, email, storage, settings, or session behavior.

```powershell
.\.venv\Scripts\python.exe manage.py test
.\.venv\Scripts\python.exe manage.py check
.\.venv\Scripts\python.exe manage.py check --deploy --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py collectstatic --dry-run --noinput --settings=siteguard.settings.prod
.\.venv\Scripts\python.exe manage.py showmigrations monitor --settings=siteguard.settings.prod
```

## Branching and Commits
Default workflow is branch-first. Keep `main` as the production authority and land direct commits there only for explicit stabilization or release work. Use short imperative commit subjects such as `Persist alerts before sending operational emails` or `Defer startup database diagnostics safely`.

## Monitoring Lifecycle
Preserve explicit handling for `UNKNOWN`, `UP`, `DOWN`, `SLOW`, `RECOVERY`, and `SSL_FAILURE`. `MonitorLog` persistence must happen before transition evaluation. Alert rows must exist before `transaction.on_commit` creates notifications or sends operational email.

## Production Safety
Do not reintroduce startup DB access in `AppConfig.ready()`. Validate behavior against PostgreSQL, not only SQLite. Preserve dedup, cooldown, repeated-DOWN suppression, recovery alerts, notification persistence, startup diagnostics, and structured monitoring traces.

## Contributor Expectations
Do not commit secrets. Use `.env.example` as the baseline. When debugging or changing production behavior, record the exact command run, the affected path, and whether the change was validated on the full suite and production deploy checks.
