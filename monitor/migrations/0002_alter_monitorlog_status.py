from django.db import migrations, models


def convert_status_to_text(apps, schema_editor):
    MonitorLog = apps.get_model('monitor', 'MonitorLog')
    for log in MonitorLog.objects.all():
        if log.status in (True, 'True', '1', 1):
            log.status = 'UP'
        else:
            log.status = 'DOWN'
        log.save(update_fields=['status'])


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='monitorlog',
            name='status',
            field=models.CharField(choices=[('UP', 'UP'), ('DOWN', 'DOWN'), ('SLOW', 'SLOW')], default='UP', max_length=10),
        ),
        migrations.RunPython(convert_status_to_text, migrations.RunPython.noop),
    ]
