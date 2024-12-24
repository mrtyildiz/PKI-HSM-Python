from datetime import datetime, timedelta

def check_date_range(date_str):
    # Şu anki tarihi ve saati al
    current_time = datetime.now()
    print(current_time)
    # Verilen tarihi datetime nesnesine dönüştür
    given_time = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S')

    # Bir saatlik bir timedelta oluştur
    one_hour_delta = timedelta(hours=1)

    # Bir saat önceki tarih ve saat'i hesapla
    one_hour_ago = current_time - one_hour_delta
    print(one_hour_ago)
    # Verilen tarih, bir saat önceki tarih ve şu anki tarih arasında kontrol yap
    if one_hour_ago < given_time < current_time:
        return f"{date_str} bir saat önceki tarih ile şu anki tarih arasında."
    else:
        return f"{date_str} bir saat önceki tarih ile şu anki tarih arasında değil."

# Örnek kullanım
given_date = '2023-12-13 10:55:00'
result_message = check_date_range(given_date)

print(result_message)
