import requests


def PKI_API_Check():
    url = "http://172.16.0.5:8000/health"  # Sağlık kontrolü endpoint'inin URL'sini buraya ekleyin

    try:
        # GET isteği gönder
        response = requests.get(url)

        # Yanıtı kontrol et
        response.raise_for_status()

        # Yanıtın içeriğini yazdır
        print("Yanıt İçeriği:", response.json())
        return "Health"
    except requests.exceptions.RequestException as err:
        # Hata durumunda hata mesajını yazdır
        print("Hata Oluştu:", err)
        return "Unhealth"
