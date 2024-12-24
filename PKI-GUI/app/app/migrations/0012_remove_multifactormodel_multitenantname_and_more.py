# Generated by Django 4.2.6 on 2023-12-29 11:38

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0011_multifactormodel_multitenantname'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='multifactormodel',
            name='MultiTenantName',
        ),
        migrations.AddField(
            model_name='userprofile',
            name='MultiTenantName',
            field=models.CharField(default=django.utils.timezone.now, max_length=80),
            preserve_default=False,
        ),
    ]
