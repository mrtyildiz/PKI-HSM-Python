# Generated by Django 4.2.6 on 2023-12-27 14:22

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='certificates',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='client_crt',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='hsmpool',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='keys',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='logs',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='multifactormodel',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='rules',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='slotlist',
            name='MultiTenantName',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='MultiTenantName',
        ),
    ]
