# Generated by Django 5.0 on 2024-01-13 14:37

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='client_crt',
            name='Token_Name',
        ),
        migrations.RemoveField(
            model_name='client_crt',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='hsmpool',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='slotlist',
            name='HSM_Pool_Name',
        ),
        migrations.RemoveField(
            model_name='keys',
            name='Token_Name',
        ),
        migrations.RemoveField(
            model_name='keys',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='multifactormodel',
            name='user_factor',
        ),
        migrations.RemoveField(
            model_name='rules',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='slotlist',
            name='created_by',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='operator',
        ),
        migrations.RemoveField(
            model_name='userprofile',
            name='user',
        ),
        migrations.DeleteModel(
            name='certificates',
        ),
        migrations.DeleteModel(
            name='client_crt',
        ),
        migrations.DeleteModel(
            name='hsmpool',
        ),
        migrations.DeleteModel(
            name='keys',
        ),
        migrations.DeleteModel(
            name='MultifactorModel',
        ),
        migrations.DeleteModel(
            name='Rules',
        ),
        migrations.DeleteModel(
            name='slotlist',
        ),
        migrations.DeleteModel(
            name='UserProfile',
        ),
    ]
