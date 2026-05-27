from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("monitor", "0015_alter_userprofile_avatar"),
    ]

    operations = [
        migrations.AddField(
            model_name="website",
            name="ssl_checked_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="website",
            name="ssl_failure_reason",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="website",
            name="ssl_status",
            field=models.CharField(default="Unknown", max_length=16),
        ),
        migrations.AddIndex(
            model_name="monitorlog",
            index=models.Index(fields=["checked_at"], name="monitor_mon_checked_0c5f4e_idx"),
        ),
    ]
