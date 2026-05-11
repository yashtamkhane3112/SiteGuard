# Release Notes

## Version

`v1`

## Highlights

- fixed Render startup order so migrations run before Gunicorn
- verified `auth_user` existence during startup
- stabilized production SQLite path
- added `/health/` for deployment verification
- added production logging configuration
- expanded admin coverage for operational models
- added CI workflow for migration and static smoke checks
- added deployment and operations documentation

## Suggested Tag

`v1.0.0-render-stable`
