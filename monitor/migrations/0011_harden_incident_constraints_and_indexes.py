from django.db import migrations, models
from django.db.models import Q


def cleanup_duplicate_active_incidents(apps, schema_editor):
    Incident = apps.get_model("monitor", "Incident")

    incidents = list(
        Incident.objects.order_by("website_id", "incident_type", "-started_at", "-created_at", "-id")
    )
    active_seen = set()

    for incident in incidents:
        if incident.is_resolved:
            continue
        key = (incident.website_id, incident.incident_type)
        if key in active_seen:
            incident.is_resolved = True
            incident.status = "RESOLVED"
            incident.resolved_at = incident.resolved_at or incident.updated_at
            incident.save(update_fields=["is_resolved", "status", "resolved_at"])
        else:
            active_seen.add(key)


class Migration(migrations.Migration):

    dependencies = [
        ("monitor", "0010_parsederror_category_parsederror_last_seen_line_and_more"),
    ]

    operations = [
        migrations.RunPython(cleanup_duplicate_active_incidents, migrations.RunPython.noop),
        migrations.AddIndex(
            model_name="monitorlog",
            index=models.Index(fields=["website", "-checked_at"], name="monitor_mon_website_8e0d66_idx"),
        ),
        migrations.AddIndex(
            model_name="incident",
            index=models.Index(fields=["website", "is_resolved", "incident_type", "-started_at"], name="monitor_inc_website_cfef0e_idx"),
        ),
        migrations.AddIndex(
            model_name="alert",
            index=models.Index(fields=["website", "alert_type", "status", "-created_at"], name="monitor_ale_website_1a96eb_idx"),
        ),
        migrations.AddConstraint(
            model_name="incident",
            constraint=models.UniqueConstraint(
                fields=("website", "incident_type"),
                condition=Q(is_resolved=False),
                name="unique_active_incident_per_type",
            ),
        ),
    ]
