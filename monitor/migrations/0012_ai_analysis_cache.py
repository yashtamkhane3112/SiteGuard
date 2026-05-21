from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('monitor', '0011_harden_incident_constraints_and_indexes'),
    ]

    operations = [
        migrations.CreateModel(
            name='AIAnalysisCache',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('scope', models.CharField(choices=[('report', 'Report'), ('error_upload', 'Error Upload'), ('incident', 'Incident')], max_length=32)),
                ('scope_key', models.CharField(max_length=160)),
                ('input_hash', models.CharField(max_length=64)),
                ('status', models.CharField(choices=[('ready', 'Ready'), ('failed', 'Failed'), ('disabled', 'Disabled')], default='ready', max_length=16)),
                ('provider', models.CharField(blank=True, max_length=64)),
                ('model_name', models.CharField(blank=True, max_length=120)),
                ('content', models.JSONField(blank=True, default=dict)),
                ('error_message', models.TextField(blank=True)),
                ('generated_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='ai_analysis_cache', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-updated_at', '-id'],
            },
        ),
        migrations.AddIndex(
            model_name='aianalysiscache',
            index=models.Index(fields=['user', 'scope', 'scope_key'], name='monitor_ai_user_scope_idx'),
        ),
        migrations.AddIndex(
            model_name='aianalysiscache',
            index=models.Index(fields=['status', '-updated_at'], name='monitor_ai_status_idx'),
        ),
        migrations.AddConstraint(
            model_name='aianalysiscache',
            constraint=models.UniqueConstraint(fields=('user', 'scope', 'scope_key'), name='unique_ai_analysis_cache_scope'),
        ),
    ]
