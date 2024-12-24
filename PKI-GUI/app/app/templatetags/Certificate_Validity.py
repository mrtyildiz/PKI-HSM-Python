from django import template
from datetime import datetime, timedelta
register=template.Library()


@register.simple_tag
def Date_Validity(date_cert):
    today = datetime.now()
    future_day = datetime(date_cert.year, date_cert.month, date_cert.day)
    Remainder_day = future_day - today
    if Remainder_day.days > 30:
        result = "primary"
    else:
        result = "warning"
   # add = SlotList.objects.count + add
    return result

@register.simple_tag
def Date_Validity2(date_cert):
    today = datetime.now()
    future_day = datetime(date_cert.year, date_cert.month, date_cert.day)
    Remainder_day = future_day - today
    if Remainder_day.days >= 0:
        result = "Valid"
    else:
        result = "Not Valid"
   # add = SlotList.objects.count + add
    return result

@register.simple_tag
def Date_Validity_Days(date_cert):
    today = datetime.now()
    future_day = datetime(date_cert.year, date_cert.month, date_cert.day)
    Remainder_day = future_day - today
    
   # add = SlotList.objects.count + add
    return Remainder_day.days+1

@register.simple_tag
def Date_Validity_HSM(date_cert):
    today = datetime.now()
        # Tarih formatını belirtin
    tarih_formati = "%d/%m/%Y %H:%M:%S"

    # Tarihi datetime objesine dönüştürün
    date_cert = datetime.strptime(date_cert, tarih_formati)
    future_day = datetime(date_cert.year, date_cert.month, date_cert.day)
    Remainder_day = future_day - today
    if Remainder_day.days > 30:
        result = "primary"
    else:
        result = "warning"
   # add = SlotList.objects.count + add
    return result

@register.simple_tag
def Date_Validity_HSM2(date_cert):
    today = datetime.now()
    # Tarih formatını belirtin
    tarih_formati = "%d/%m/%Y %H:%M:%S"

    # Tarihi datetime objesine dönüştürün
    date_cert = datetime.strptime(date_cert, tarih_formati)

    future_day = datetime(date_cert.year, date_cert.month, date_cert.day)
    Remainder_day = future_day - today
    if Remainder_day.days >= 0:
        result = "Valid"
    else:
        result = "Not Valid"
   # add = SlotList.objects.count + add
    return result
