from django.db import models
# Create your models here.
from django.db.models.signals import post_save
from django.contrib.auth.models import AbstractUser
from django.dispatch import receiver

#####

from django.db.models.signals import pre_save

from django.utils import timezone

from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest
from django.contrib.auth.models import User, Group, Permission
from django.contrib.auth.models import Permission, ContentType
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Group
from django.db import transaction
import os

class Logs(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    Log_Sensitives_Choices = [
        ('DEBUG','DEBUG'),
        ('INFO','INFO'),
        ('WARNING','WARNING'),
        ('ERROR','ERROR'),
        ('CRITICAL','CRITICAL'),
    ]
    Log_Sensitives = models.CharField(choices=Log_Sensitives_Choices, max_length=9)
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    Log_Process_Choices = [
        ('System','System'),
        ('Upload','Upload'),
        ('Edit','Edit'),
        ('Delete','Delete'),
        ('Signature','Signature'),
        ('Create','Create'),
        ('Encryption','Encryption'),
        ('Decryption','Decryption'),
    ]
    Log_Process = models.CharField(choices=Log_Process_Choices, max_length=10)
    created_at = models.DateTimeField(auto_now_add=True)
    Description = models.CharField(max_length=255)
    
    
    def __str__(self):
        return self.Log_Sensitives


@receiver(pre_save, sender=Logs)
def set_Logs_created_by(sender, instance, **kwargs):
    if not instance.created_by:
        # Eğer request objesi varsa ve kullanıcı authenticated ise
        if hasattr(instance, '_request') and instance._request.user.is_authenticated:
            instance.created_by = instance._request.user
            instance.MultiTenantName = os.environ.get("NAMESPACE")
        # Eğer request objesi varsa ve kullanıcı anonymous ise
        elif hasattr(instance, '_request') and isinstance(instance._request.user, AnonymousUser):
            instance.created_by = None
            instance.MultiTenantName = os.environ.get("NAMESPACE")
        # Eğer request objesi yoksa ya da kullanıcı authenticated değilse
        else:
            instance.created_by = None
            instance.MultiTenantName = os.environ.get("NAMESPACE")
# class SSL_Rules(models.Model):
