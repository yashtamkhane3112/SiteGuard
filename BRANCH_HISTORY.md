# Branch History

Detailed branch archival notes live in [docs/branch-history.md](docs/branch-history.md).

## Authoritative Production Line

`main` is the authoritative production branch and already contains:

- Neon PostgreSQL production support
- DB-backed sessions
- alert persistence before email dispatch
- explicit first-incident lifecycle tracking
- startup-safe runtime diagnostics

## Historical Milestones

- `status-sync-final`: Render-stable release milestone
- `neon-postgres-migration`: production DB transition
- `stabilize-alert-execution-tracing`: monitoring/alert observability
- `fix-alert-persistence-on-commit`: durable alert persistence ordering
- `behavior-initial-down-alerting`: explicit first DOWN handling
- `investigate-alert-persistence-failure`: PostgreSQL timing fix for first alerts

## Archive Policy

Historical branches are preserved for forensic traceability and should not be deleted casually. Future work should branch from `main`.
