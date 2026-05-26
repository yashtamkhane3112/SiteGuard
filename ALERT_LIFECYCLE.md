# Alert Lifecycle

## State Machine

Monitoring transitions are evaluated across:

- `UNKNOWN`
- `UP`
- `DOWN`
- `SLOW`
- `RECOVERY`
- `SSL_FAILURE`

## Processing Order

1. Persist `MonitorLog`
2. Evaluate incident state
3. Create or reuse the relevant `Incident`
4. Persist `Alert` row before any downstream side effects
5. Use `transaction.on_commit` to create notifications and send operational email after durability is guaranteed

## PostgreSQL Fix

The production alert bug came from inferring “new incident” via timestamp equality:

- `created_at == updated_at`
- `started_at == checked_at`

That was fragile on PostgreSQL timing and precision. SiteGuard now tracks first-incident creation explicitly inside the incident creation path, so first `UNKNOWN -> DOWN` and first SSL failures correctly create:

- incident
- alert row
- notification
- operational email

## Preserved Behaviors

- alert deduplication
- cooldown suppression
- repeated DOWN suppression
- recovery alert generation
- notification persistence
- operational email dispatch after commit

## Observability

Structured monitoring traces remain in place for:

- monitor result persistence
- incident state transitions
- alert creation
- `on_commit` callback execution
- notification processing
