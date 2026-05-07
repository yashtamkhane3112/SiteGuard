from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


def create_profiles_for_existing_users(apps, schema_editor):
    User = apps.get_model('auth', 'User')
    UserProfile = apps.get_model('monitor', 'UserProfile')
    for user in User.objects.all():
        UserProfile.objects.get_or_create(user=user)


class Migration(migrations.Migration):

    dependencies = [
        ('monitor', '0005_website_alerts_enabled_website_email_notifications_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='UserProfile',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('avatar', models.FileField(blank=True, null=True, upload_to='avatars/')),
                ('timezone', models.CharField(default='UTC', max_length=64)),
                ('email_alerts_enabled', models.BooleanField(default=True)),
                ('ssl_alerts_enabled', models.BooleanField(default=True)),
                ('incident_alerts_enabled', models.BooleanField(default=True)),
                ('marketing_emails_enabled', models.BooleanField(default=False)),
                ('monitoring_frequency', models.CharField(choices=[('1', '1 min'), ('5', '5 min'), ('15', '15 min'), ('30', '30 min')], default='5', max_length=4)),
                ('two_factor_enabled', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='profile', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['user__username'],
            },
        ),
        migrations.RunPython(create_profiles_for_existing_users, migrations.RunPython.noop),
    ]
