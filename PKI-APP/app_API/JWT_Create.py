import jwt
import uuid
from datetime import datetime, timedelta
# FastAPI uygulamasını başlatın

# JWT ayarlarını belirleyin (örnek amaçlı kullanılan bir anahtar ve süre)
SECRET_KEY = "SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # JWT'nin geçerlilik süresi (dakika cinsinden)

# JWT oluşturma işlevi
def create_jwt_token(crt_name):
    expiration = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "crt_name": crt_name,  # Benzersiz bir kullanıcı kimliği
        "exp": expiration,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

def Verifty(Token):
    try:
        payload = jwt.decode(Token, SECRET_KEY, algorithms=[ALGORITHM])
        CRTName = payload.get("crt_name")
        message = "The certificate named "+str(CRTName)+" is valid"
        result = {"Message:": message}
    except jwt.JWTError:
        message = "The certificate is not valid"
        result = {"Message:": message}
    return result
# name = "procenne.crt"
# na = create_jwt_token(name)
# print(na)

# Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjcnRfbmFtZSI6InByb2Nlbm5lLmNydCIsImV4cCI6MTY5NTk5NjM0MX0.pruLKJRuv8wSVz_wZr3DZ_mc8-2tnug580fqJ_h2_8E"
# a = Verifty(na)
# print(a)