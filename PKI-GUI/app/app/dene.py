from django.db import models
from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.utils import timezone
from django.contrib.auth.models import AnonymousUser
from django.http import HttpRequest

class YourModel(models.Model):
    # Diğer alanlarınız
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)

@receiver(pre_save, sender=YourModel)
def set_created_by(sender, instance, **kwargs):
    if not instance.created_by:
        # Eğer request objesi varsa ve kullanıcı authenticated ise
        if hasattr(instance, '_request') and instance._request.user.is_authenticated:
            instance.created_by = instance._request.user
        # Eğer request objesi varsa ve kullanıcı anonymous ise
        elif hasattr(instance, '_request') and isinstance(instance._request.user, AnonymousUser):
            instance.created_by = None
        # Eğer request objesi yoksa ya da kullanıcı authenticated değilse
        else:
            instance.created_by = None

# View fonksiyonunuz içinde request objesini model instance'ına eklemek için
# aşağıdaki gibi bir yöntem kullanabilirsiniz:

def your_view(request):
    # ... (View kodları)
    instance = YourModel()
    instance._request = request
    instance.save()
