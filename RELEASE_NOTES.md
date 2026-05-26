# Release Notes

## Version

`v2.1.0-production-stable`

## Highlights

- fixed PostgreSQL-sensitive first-incident gating so first `UNKNOWN -> DOWN` transitions create incidents, alerts, notifications, and operational emails reliably on Neon PostgreSQL
- preserved alert durability by keeping alert persistence ahead of `transaction.on_commit` notification and Brevo email dispatch
- verified operational alerts, password resets, DB-backed sessions, Cloudinary-backed media, and Render deployment behavior
- removed Django startup database access from `AppConfig.ready()` by deferring DB/session diagnostics to a safe runtime connection signal
- added production-grade server-side pagination for logs, alerts, incidents, notifications, weekly report history, and analyzer investigation groups
- moved notification priority ordering into SQL and tightened list-view rendering for better performance on larger datasets
- improved responsive dark-theme pagination controls, list readability, and mobile layout consistency without changing backend monitoring behavior
- normalized production documentation, branch history, contributor guidance, and SiteGuard branding across the repository

## Suggested Tag

`v2.1.0-production-stable`
