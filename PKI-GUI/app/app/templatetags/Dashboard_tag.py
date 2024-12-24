from django import template
from datetime import datetime

register=template.Library()


def Remaining_Day(target_Date):
    # Şu anki tarihi al
    Now_Date = datetime.now()

    # Hedef tarihi datetime objesine çevir
    target_Date_obje = datetime.strptime(target_Date, "%d/%m/%Y %H:%M:%S")

    # Kalan günleri hesapla
    kalan_gun = (target_Date_obje - Now_Date).days

    return kalan_gun

@register.simple_tag
def Remaining_Day_HTML(target_Date):
    Days = Remaining_Day(target_Date)
    return Days
