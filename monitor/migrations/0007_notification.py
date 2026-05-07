from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0006_userprofile'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='Notification',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('title', models.CharField(max_length=255)),
                ('message', models.TextField()),
                ('notification_type', models.CharField(choices=[('outage', 'Outage'), ('recovery', 'Recovery'), ('ssl', 'SSL'), ('report', 'Report'), ('warning', 'Warning'), ('info', 'Info')], max_length=20)),
                ('severity', models.CharField(choices=[('critical', 'Critical'), ('warning', 'Warning'), ('success', 'Success'), ('info', 'Info')], default='info', max_length=20)),
                ('is_read', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('related_incident', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='monitor.incident')),
                ('related_website', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='notifications', to='monitor.website')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='notifications', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at', '-id'],
                'indexes': [
                    models.Index(fields=['user', 'is_read', '-created_at'], name='monitor_noti_user_id_72cf32_idx'),
                    models.Index(fields=['user', 'notification_type', 'severity'], name='monitor_noti_user_id_3548e1_idx'),
                ],
            },
        ),
    ]
