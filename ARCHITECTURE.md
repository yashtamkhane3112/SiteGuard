# Architecture

## Application Layout

- `siteguard/`: Django settings, URL configuration, ASGI/WSGI entrypoints, validation helpers
- `monitor/`: monitoring engine, alerts, incidents, notifications, email delivery, AI services, storage adapters, views, tests, and management commands
- `templates/`: server-rendered UI
- `static/`: source static assets
- `start.sh`: Render-safe startup sequence
- `render.yaml`: Render service definition

## Runtime Model

The Django web process is the authoritative runtime for:

- website creation
- monitoring checks
- incident persistence
- alert persistence
- notification creation
- operational email dispatch

The Render cron service does not run its own ORM worker. It calls the protected monitoring endpoint so the web service performs the writes.

## Data and Storage

- production database: Neon PostgreSQL
- local database: SQLite only
- session persistence: Django DB-backed sessions
- media storage: Cloudinary
- analyzer uploads: Cloudinary raw storage

## Email and AI

- transactional email: Brevo API
- password reset, operational alerts, and recovery emails share the same transport
- AI analysis: optional Gemini integration for incident, error, and report analysis

## Startup Hygiene

`AppConfig.ready()` no longer touches the database. AI and storage diagnostics log during initialization, while DB/session diagnostics are deferred until the first real database connection.
