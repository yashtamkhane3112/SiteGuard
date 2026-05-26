# Branch History

## Authoritative Branch

`main` is the production branch.

Current production fix chain on `main` includes:

- Neon PostgreSQL support
- `DATABASE_URL` parsing with SSL-ready production configuration
- DB-backed sessions
- alert persistence before email dispatch
- explicit initial DOWN handling
- PostgreSQL-safe incident creation gating
- startup-safe deferred DB/session diagnostics

## Historical Branches Preserved for Archive

### Alert and monitoring branches

- `neon-postgres-migration`
  - introduced the production PostgreSQL transition and early alert delivery diagnostics
- `stabilize-alert-execution-tracing`
  - added end-to-end monitoring and alert tracing
- `fix-alert-persistence-on-commit`
  - ensured alert rows are persisted before operational emails and notifications execute
- `behavior-initial-down-alerting`
  - made first `UNKNOWN -> DOWN` behavior explicit
- `investigate-alert-persistence-failure`
  - fixed PostgreSQL-sensitive first-incident gating by replacing timestamp equality with explicit lifecycle tracking

### Deployment, email, and storage branches

- `postgres-migration`
  - early PostgreSQL/session transition work later superseded by the Neon production path
- `temp-render-session-durability`
  - temporary session fallback branch preserved for history
- `brevo-email-testing`
  - Brevo SMTP validation work
- `brevo-api-transport`
  - final Brevo API transport adoption
- `resend-backup`, `resend-production-cleanup`
  - archived email experiments that are not the current production path
- `cloudinary-media-storage`
  - introduced Cloudinary production storage

### Milestone and backup branches

- `status-sync-final`
  - release milestone before the current production hardening sequence
- `smtp-working-stable-backup`
  - preserved SMTP-era stable baseline
- `backup-main-before-brevo-*`
  - point-in-time backups before email transport changes

## Why They Are Preserved

These branches document the forensic trail for:

- session durability fixes
- Render deployment stabilization
- email transport changes
- alert persistence debugging
- PostgreSQL timing regressions

Do not delete them casually. Future release work should branch from `main`, not from archived debugging branches.
