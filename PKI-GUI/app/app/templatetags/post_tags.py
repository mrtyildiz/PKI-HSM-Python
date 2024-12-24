from django import template
import hashlib

register=template.Library()

def calculate_md5(input_string):
    md5_hash = hashlib.md5()
    md5_hash.update(input_string.encode("utf-8"))
    return md5_hash.hexdigest()

@register.simple_tag
def slot_PIN_MD5(Slot_PIN):
    MD5Sum = calculate_md5(Slot_PIN)
    return MD5Sum