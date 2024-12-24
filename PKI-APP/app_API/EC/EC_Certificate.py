from PyKCS11 import *

def create_cert_using_hsm(pkcs11_lib_path, pin, label, cert_path):
    pkcs11 = PyKCS11Lib()
    pkcs11.load(pkcs11_lib_path)

    try:
        slots = pkcs11.getSlotList()

        # Bir slot seçin (örneğin, ilk slot)
        slot = slots[0]

        # Token'a bağlan
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        
        # Pin'i kullanarak oturum aç
        session.login(pin)

        # HSM üzerindeki ECDSA anahtar çiftini bulun
        key_handles = session.findObjects(template=[
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, CKK_EC),
        ])

        if not key_handles:
            raise RuntimeError("Belirtilen etikete sahip bir ECDSA özel anahtarı bulunamadı.")

        private_key_handle = key_handles[0]

        # ECDSA genel anahtarını elde et
        ec_params = session.getAttributeValue(private_key_handle, [CKA_EC_PARAMS])[0]
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP384R1(), ec_params)

        # Sertifikayı oluştur
        subject = x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, "example.com"),
        ])
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject
        ).public_key(
            public_key
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)
        ).sign(PyKCS11Backend.load_ecdsa_private_key(private_key_handle), hashes.SHA256(), default_backend())

        # Sertifikayı dosyaya yaz
        with open(cert_path, "wb") as cert_file:
            cert_file.write(cert.public_bytes(serialization.Encoding.PEM))

        # Oturumu kapat
        session.logout()
        session.closeSession()

    except PyKCS11Error as e:
        print(f"Hata: {e}")



if __name__ == "__main__":
    pkcs11_lib_path = "/lib64/libprocryptoki.so"  # PKCS#11 kütüphanesi
    pin = "1111"  # Token PIN'i
    label = "ansiX9p384r1priv"  # Anahtar etiketi
    cert_path = "example_cert.pem"  # Sertifika dosya yolu

    create_cert_using_hsm(pkcs11_lib_path, pin, label, cert_path)
