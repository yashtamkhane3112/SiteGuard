import monitor.models
import monitor.storage
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0013_alter_uploadedlog_file_raw_storage'),
    ]

    operations = [
        migrations.AlterField(
            model_name='uploadedlog',
            name='file',
            field=models.FileField(
                storage=monitor.storage.AnalyzerUploadStorage(),
                upload_to=monitor.models.uploaded_log_file_path,
            ),
        ),
    ]
