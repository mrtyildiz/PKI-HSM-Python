from django.http import HttpResponse
from django.shortcuts import render
#from .middleware import verify_license
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_license():
    try:
        # Genel anahtarınızı yükleyin
        with open("/app/app/Lisans/public.key", "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())
        with open("/app/app/Lisans/license_info.json", "r") as key_file:
            license_info = key_file.read()
        with open('/app/app/Lisans/signature', 'rb') as file:
            signature = file.read()
        # İmzayı doğrulayın
        public_key.verify(
            signature,
            license_info.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

class LicenseMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        license_info = "license_information_here"
        signature = "signature_from_server"

        if not verify_license():
            return render(request, 'Lisans.html', status=403)
          #  return HttpResponse("Lisansınız geçersiz veya süresi dolmuş.", status=403)

        response = self.get_response(request)
        return response
