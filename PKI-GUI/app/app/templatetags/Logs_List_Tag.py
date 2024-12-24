
from django import template
import hashlib

# Hedef URL
register=template.Library()

@register.simple_tag
def total_slot(add):
   # add = SlotList.objects.count + add
    return add

@register.simple_tag
def SensitivesLogs(Sensitives):
    if Sensitives == 'INFO':
        result = "info"
    elif Sensitives == 'DEBUG':
        result = "INFO"
    if Sensitives == 'WARNING':
        result = "warning"
    elif Sensitives == 'ERROR':
        result = "danger"
    elif Sensitives == 'CRITICAL':
        result = "danger"
    else:
        result = "primary"
    return result


@register.simple_tag
def Process_Log(Process):
   if Process == 'System':
        result = 'primary'
   elif Process == 'Upload':
        result = 'secondary'
   elif Process == 'Edit':
        result = 'info'
   elif Process == 'Delete':
        result = 'danger'
   elif Process == 'Signature':
        result = 'warning'
   elif Process == 'Create':
        result = 'primary'
   elif Process == 'Encryption':
        result = 'primary'
   elif Process == 'Decryption':
        result = 'primary'
   else:
       result = 'primary'
   return result