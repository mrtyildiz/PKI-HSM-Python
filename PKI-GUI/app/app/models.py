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
from tenant_schemas.models import TenantMixin

class Client(TenantMixin):
    name = models.CharField(max_length=100)
    paid_until = models.DateField()
    on_trial = models.BooleanField()
    created_on = models.DateField(auto_now_add=True)
    def __str__(self):
        return self.name
# class Multi_Tenant(models.Model):
#     tenant = models.CharField(max_length=50)
#     def __str__(self):
#         return self.tenant

# class TenantUser(AbstractUser):
#     tenant = models.ForeignKey(Multi_Tenant, on_delete=models.CASCADE, related_name='users', verbose_name=('tenant'))
#     # Diğer özel alanları burada tanımlayabilirsiniz
#     groups = models.ManyToManyField(
#         'auth.Group',
#         verbose_name=('groups'),
#         blank=True,
#         help_text=('The groups this user belongs to.'),
#         related_name='tenant_users',  # Burada related_name özelliği belirtilmiştir
#     )
#     user_permissions = models.ManyToManyField(
#         'auth.Permission',
#         verbose_name=('user permissions'),
#         blank=True,
#         help_text=('Specific permissions for this user.'),
#         related_name='tenant_users_permissions',  # Burada related_name özelliği belirtilmiştir
#     )

#     def __str__(self):
#         return self.username

class UserProfile(models.Model):
    MultiTenantName = models.CharField(max_length=80)
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    UserTypeChoices = [
        ('Django','Django'),
        ('Ldap','Ldap'),
        ('AD','AD'),
    ]
    UserType = models.CharField(choices=UserTypeChoices, max_length=10, default='Django')
    TwoFacörType = [
        ('Disable','Disable'),
        ('Enable','Enable'),
    ]
    TwoFactor = models.CharField(choices=TwoFacörType, max_length=10, default='Disable')
    telephone_number = models.CharField(max_length=15)
    MulfiFactorValue = [
        ('Disable','Disable'),
        ('Enable','Enable'),
    ]
    MulfiFactor = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    UserTypeValue = [
        ('System_User','System_User'),
        ('Operator_User','Operator_User'),
        ('Client_User','Client_User'),
    ]
    USerType = models.CharField(choices=UserTypeValue, max_length=16, default='Client_User')
    operator = models.ForeignKey(User, related_name='clients', null=True, blank=True, on_delete=models.SET_NULL)
    OTP_Value = models.CharField(max_length=50)
    QR_Path = models.CharField(max_length=100)
    def __str__(self):
        StrUser = str(self.user)
        return StrUser

@receiver(post_save, sender=UserProfile)
@transaction.atomic  # Bu, veritabanı işlemlerinin atomik (atomic) bir şekilde gerçekleştirilmesini sağlar.
def add_user_to_system_group(sender, instance, created, **kwargs):


    if instance.USerType == 'System_User':
        system_group, created = Group.objects.get_or_create(name='SystemGroup')
        user = instance.user  # UserProfiLogse modelindeki User alanını alın
        system_group.user_set.add(user)  # Kullanıcıyı var olan gruba ekler
        user.is_staff = True
        user.is_superuser = True
        user.save()
        print("Kullanıcı güncellendi:", user.username)
    elif instance.USerType == 'Operator_User':
        operator_group, created = Group.objects.get_or_create(name='OperatorGroup')
        user = instance.user
        operator_group.user_set.add(user)
        user.is_staff = True
        user.is_superuser = False  # Eğer operatörse, süper kullanıcı olmasını istemiyorsanız
        user.save()
        print("Operatör_User güncellendi:", user.username)
    else:
        print("Diğer kullanıcı türleri işlenmedi:", instance.USerType)


class MultifactorModel(models.Model):
    
    user_factor = models.OneToOneField(User, on_delete=models.CASCADE)
    MulfiFactorValue = [
        ('Disable','Disable'),
        ('Enable','Enable'),
    ]
    Keys_Create = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Valid_Load_Request = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    CA_CRT = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    CRT_Delete_Client = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    crt_load_client = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    CSR_HSM_CRT_Request = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    CA_CRT_Delete = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Keys_Delete = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Slot_delete = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    hsm_slot_update = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Slot_List = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Pool_Active = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Pool_delete = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Pool_create = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    Pool_Upload = models.CharField(choices=MulfiFactorValue, max_length=10, default='Disable')
    def __str__(self):
        StrUser = str(self.user_factor)
        return StrUser

@receiver(post_save, sender=User)
def create_multifactor_model(sender, instance, created, **kwargs):
    if created and not hasattr(instance, 'multifactormodel'):
        # Check if MultifactorModel already exists for the user
        if not MultifactorModel.objects.filter(user_factor=instance).exists():
            MultifactorModel.objects.create(user_factor=instance)

# class hsmpool(models.Model):
# #    tenant_id = models.IntegerField(default=0)
# #    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
#     HSM_Pool_Name = models.CharField(max_length=100)
#     HSM_IP = models.CharField(max_length=100)
#     HSM_Port = models.CharField(max_length=100)
#     Status_Choices = [
#         ('active','active'),
#         ('passive','passive'),
#     ]
#     HSM_Status = models.CharField(choices=Status_Choices, max_length=7, default='passive')
#     Type_HSM_Choices = [
#         ('single','single'),
#         ('multi','multi')
#     ]
#     HSM_Pool_Type = models.CharField(choices=Type_HSM_Choices, max_length=7)
    

#     def __str__(self):
#         return self.HSM_Pool_Name

class hsmpool(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    HSM_Pool_Name = models.CharField(max_length=100, unique=True)
    HSM_IP = models.CharField(max_length=100)
    HSM_Port = models.CharField(max_length=100)
    Status_Choices = [
        ('active','active'),
        ('passive','passive'),
    ]
    HSM_Status = models.CharField(choices=Status_Choices, max_length=7, default='passive')
    Type_HSM_Choices = [
        ('single','single'),
        ('multi','multi')
    ]
    HSM_Pool_Type = models.CharField(choices=Type_HSM_Choices, max_length=7)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.HSM_Pool_Name

@receiver(pre_save, sender=hsmpool)
def set_hsmpool_created_by(sender, instance, **kwargs):
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


class slotlist(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    HSM_Pool_Name = models.ForeignKey(hsmpool, on_delete=models.CASCADE)
    TokenName = models.CharField(max_length=100, unique=True)
    UserPIN = models.CharField(max_length=100)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.TokenName

@receiver(pre_save, sender=slotlist)
def set_slotlist_created_by(sender, instance, **kwargs):
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

class keys(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    SlotID = models.IntegerField()
    Token_Name = models.ForeignKey(slotlist, on_delete=models.CASCADE)
    Type_Chooice = [
        ('AES','AES'),
        ('RSA','RSA'),
        ('EC','EC')
    ]
    Keys_Type = models.CharField(choices=Type_Chooice, max_length=4)
    Keys_Name = models.CharField(max_length=100)
    BIT_Choices = [
        ('256','256'),
        ('128','128'),
        ('512','512'),
        ('1024','1024'),
        ('2048','2048'),
        ('3072','3072'),
        ('4096','4096'),
        ('ansiX9p192r1','ansiX9p192r1'),
        ('ansiX9p256r1','ansiX9p256r1'),
        ('ansiX9p384r1','ansiX9p384r1'),
        ('brainpoolP192r1','brainpoolP192r1'),
        ('brainpoolP224r1','brainpoolP224r1'),
        ('brainpoolP256r1','brainpoolP256r1'),
        ('brainpoolP320r1','brainpoolP320r1'),
        ('nistp192','nistp192'),
        ('nistp224','nistp224'),
        ('nistp521','nistp521'),
        ('prime192v1','prime192v1'),
        ('prime192v2','prime192v2'),
        ('prime192v3','prime192v3'),
        ('prime256v1','prime256v1'),
        ('prime384v1','prime384v1'),
        ('secp192k1','secp192k1'),
        ('secp192r1','secp192r1'),
        ('secp224r1','secp224r1'),
        ('secp256k1','secp256k1'),
        ('secp256r1','secp256r1'),
        ('secp384r1','secp384r1'),
        ('secp521r1','secp521r1'),
    ]
    Key_BIT = models.CharField(choices=BIT_Choices, max_length=16)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    

    def __str__(self):
        return self.Keys_Name

@receiver(pre_save, sender=keys)
def set_keys_created_by(sender, instance, **kwargs):
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

class certificates(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    Slot_ID = models.IntegerField()
    Token_Name = models.ForeignKey(slotlist, on_delete=models.CASCADE)
    KeyName = models.CharField(max_length=100)
    Certificate_Name = models.CharField(max_length=100)
    Data_Start = models.DateField()
    Data_End = models.DateField()
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.Certificate_Name

@receiver(pre_save, sender=certificates)
def set_certificates_created_by(sender, instance, **kwargs):
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


class Logs_Bak(models.Model):
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


class client_crt(models.Model):
#    tenant_id = models.IntegerField(default=0)
#    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
    MultiTenantName = models.CharField(max_length=80)
    name = models.CharField(max_length=100, unique=True)
    Slot_ID = models.IntegerField()
    Token_Name = models.ForeignKey(slotlist, on_delete=models.CASCADE)
    KeyName = models.CharField(max_length=100)
    Certificate_Name = models.CharField(max_length=100)
    Data_Start = models.DateField()
    Data_End = models.DateField()
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    

    def __str__(self):
        return self.Certificate_Name
    
@receiver(pre_save, sender=client_crt)
def set_client_crt_created_by(sender, instance, **kwargs):
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


    
# class Certificate_Info(models.Model):
# #    tenant_id = models.IntegerField(default=0)
# #    tenant_user = models.ForeignKey(TenantUser, on_delete=models.CASCADE, default=0)
#     KeyName = models.CharField(max_length=100)
#     Certificate_Name = models.CharField(max_length=100)
#     Country = models.CharField(max_length=2)
#     Company = models.CharField(max_length=100)
#     Common_Name = models.CharField(max_length=100)
#     Serial_Number = models.IntegerField()

#     def __str__(self):
#         return self.KeyName
    
class Rules(models.Model):
    MultiTenantName = models.CharField(max_length=80)
    Rules_Name = models.CharField(max_length=150, unique=True)
    Pool_Name = models.CharField(max_length=150)
    SlotName = models.CharField(max_length=150)
    SlotID = models.IntegerField()
    Certificate_Name = models.CharField(max_length=150)
    Sending_Time = models.DateTimeField()
    Sending_Person = models.CharField(max_length=150)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

    def __str__(self):
        return self.Rules_Name

@receiver(pre_save, sender=Rules)
def set_Rules_created_by(sender, instance, **kwargs):
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
