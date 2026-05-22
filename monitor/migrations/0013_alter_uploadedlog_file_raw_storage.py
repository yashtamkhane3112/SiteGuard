import monitor.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0012_ai_analysis_cache'),
    ]

    operations = [
        migrations.AlterField(
            model_name='uploadedlog',
            name='file',
            field=models.FileField(
                storage=monitor.models.get_uploaded_log_storage,
                upload_to=monitor.models.uploaded_log_file_path,
            ),
        ),
    ]
