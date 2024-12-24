# Generated by Django 4.2.6 on 2024-01-14 19:22

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('app', '0014_alter_slotlist_tokenname'),
    ]

    operations = [
        migrations.CreateModel(
            name='Logs_Bak',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('MultiTenantName', models.CharField(max_length=80)),
                ('Log_Sensitives', models.CharField(choices=[('DEBUG', 'DEBUG'), ('INFO', 'INFO'), ('WARNING', 'WARNING'), ('ERROR', 'ERROR'), ('CRITICAL', 'CRITICAL')], max_length=9)),
                ('Log_Process', models.CharField(choices=[('System', 'System'), ('Upload', 'Upload'), ('Edit', 'Edit'), ('Delete', 'Delete'), ('Signature', 'Signature'), ('Create', 'Create'), ('Encryption', 'Encryption'), ('Decryption', 'Decryption')], max_length=10)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('Description', models.CharField(max_length=255)),
                ('created_by', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
