import pyotp
import qrcode
import random
import string

def generate_random_numeric_string(length):
    digits = string.digits
    random_numeric_string = ''.join(random.choice(digits) for _ in range(length))
    return random_numeric_string


def QRCreate(UserName):
    # Kullanıcıya özel bir anahtar oluşturun
    user_secret = pyotp.random_base32()

    # TOTP nesnesini oluşturun
    totp = pyotp.TOTP(user_secret)
    # TOTP anahtarını alın
    otp_key = totp.now()
    # QR kodu URI'sini alın
    uri = totp.provisioning_uri(name=UserName, issuer_name='Procenne PKI')
    # QR kodunu oluşturun
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    # Örnek: 6 karakter uzunluğunda rastgele bir sayı string
    random_numeric_string = generate_random_numeric_string(6)
    print(random_numeric_string)
    # QR kodunu kaydedin
    save_img = "/app/app/static/img/QR_User/qrcod"+str(random_numeric_string)+".png"
    img.save(save_img)
    Static_IMG = "qrcod"+str(random_numeric_string)+".png"
    User_details = { 'user_secret':user_secret, 'IMG_URL':Static_IMG}
    # json_data = json.dumps(User_details)
    # parsed_data = json.loads(json_data)
    # print(parsed_data['IMG_URL'])
    return User_details

# user = "Murat"
# QRCreate(user)

def verify_totp(user_secret, user_input):
    # TOTP nesnesini oluşturun
    totp = pyotp.TOTP(user_secret)

    # Kullanıcıdan alınan kodu doğrulayın
    if totp.verify(user_input):
        return True
    else:
        return False

# # Kullanıcıdan alınan TOTP kodunu doğrulama örneği
# user_input = input("Lütfen TOTP kodunu girin: ")

# if verify_totp(user_secret, user_input):
#     print("Doğrulama başarılı!")
# else:
#     print("Doğrulama başarısız!")
