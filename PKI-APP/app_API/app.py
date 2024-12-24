from pydantic import BaseModel
from RSAKeyCreate import RSA_Create
from CA_Certificate_Request import CARequestCertificate
from CA_Certificate_Request2 import CARequestCertificate2
from Certificate_Loads import Certificate_Load
from fastapi import FastAPI, UploadFile, Form, HTTPException
import os
from CSR_To_CRT import csr_t_crt
from Postgresql_Insert import Insert_Certificate
from File_Read import Read_File_Func

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from pathlib import Path
from User_Obje_Create import User_Obje_Create_Func
from User_Obje_Verifty import User_Obje_Verifty_Func
from Certificate_Info import Cert_Info
from Certificate_Info_Single import Cert_InfoSing
from CRTVerity import VeriftyCRT

from JWT_Create import create_jwt_token, Verifty
from ObjeRemove import RemoveObje
from CSR_Request import CSR_Create
from CSR_HSM_CRT import HSM_CSR
from CSR_HSM_CRT_new import CSR_Create_New
from Keys_Create import AES_Creates
from Two_Factor_Random import RandomCharacter
from AES_Encrypt_Decrypt import AESEncrypt,AESDEcryption
from Public_Export import PublicExport
from CA_Export import CrtExport
from Token_Check import Check_Token
from fastapi.responses import JSONResponse
from User_Info import User_Infos
from User_Obje_Delete import User_Delete
from Active_HSM_Pool import ConfigFileWrite
from Find_Label_Priv import Find_Label_Obje
from Obje_URL import get_tokens
from Slot_PIN_Find import Slot_Find
from EC.EC_Create_Main import EC_Create
from verify_certificate_create import verify_certificate
import json
import base64
from FileEncryptPYHSM import *
from Slot_Label_List import Slot_Label_Func
from Slot_Intialized_Merge import Token_Create
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
app = FastAPI()

class Token_Create_Model(BaseModel):
    ho_pin: str
    ha_pin: str
    Token_Label: str
    SO_PIN: str
    User_PIN:str

class EC_Create_Model(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyLabel: str
    Algoritma: str

class FileEncDec(BaseModel):
    ID: int
    PIN: str
    init_vector: str
    KName: str
    FNamePath: str

class FindLabelObje(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    Obje_Label: str

class Obje_URL_Find(BaseModel):
    ID: int
    PIN: str

class ActiveHSMModel(BaseModel):
    IP_Address: str
    Port_Address: str
class RSA(BaseModel):
    ID: int
    PIN: str
    KName: str
    BIT: int

class AES(BaseModel):
    SlotID: int
    SlotPIN: str
    AES_KeyName: str
    BIT: int

class CARequest(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    PrivateKeyName: str
    CommonName: str
    OrganizationName: str
    CountryName: str

class CARequest_New(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    PrivateKeyName: str
    Days: int
    data: str
class CertificateLoad(BaseModel):
    SlotID: int
    SlotPIN: str
    CertificateFile: str
    CertificateName: str

class UserData(BaseModel):
    SlotID: int
    SlotPIN: str
    UserName: str
    Parola: str

class InfoCertificate(BaseModel):
    ID: int
    PIN: str

class InfoUser(BaseModel):
    ID: int
    PIN: str

class InfoCertificateSing(BaseModel):
    ID: int
    PIN: str
    CertificateName: str

class Token(BaseModel):
    tokens: str

class ObjeRemove(BaseModel):
    ID: int
    Slot_PIN: str
    ObjeType: str
    ObjeLabel: str

class CSR_HSM_Request_Data(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    Country: str
    City: str
    Company: str
    Common_Name: str
    CompanyID: str

class CSR_HSM_Request_Data_New(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    Company: str
    Json_Data: str

class verifty_crt_Request_model(BaseModel):
    SlotID: int
    SlotPIN: str
    CA_CRT: str
    CRT_Name: str
class RandomChar(BaseModel):
    SlotID: int
    SlotPIN: str
    Character: int

class AESEnc_data(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    Data: str
    init_Vector_str: str
class ExpPublic(BaseModel):
    SlotID: int
    SlotPIN: str
    PublicKeyName: str
class ExportCert(BaseModel):
    SlotID: int
    CertificateName: str

class TokenN(BaseModel):
    TokenName: str

class UserRemove(BaseModel):
    SlotID: int
    SlotPIN: str
    UserName: str

class SlotPINFind_Model(BaseModel):
    API_Key: str
    Action: str
    Strings_Slot_PIN: str

class Verify_Certificate_Key_Model(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    CRT_Name: str

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

def verify_license():
    try:
        # Genel anahtarınızı yükleyin
        with open("/app/Lisans/public.key", "rb") as key_file:
            public_key = load_pem_public_key(key_file.read())
        with open("/app/Lisans/license_info.json", "r") as key_file:
            license_info = key_file.read()
        with open('/app/Lisans/signature', 'rb') as file:
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


@app.middleware("http")
async def license_middleware(request: Request, call_next):
    license_info = "license_information_here"
    signature = "signature_from_server"

    if not verify_license():
        # Lisans kontrolü başarısız olursa, bir hata sayfası döndür
        content = "<html><body><h1>Lisans Hatası</h1><p>Lisansınız geçersiz veya süresi dolmuş.</p></body></html>"
        return HTMLResponse(content=content, status_code=403)

    response = await call_next(request)
    return response

@app.get("/health", status_code=200)
async def health_check():
    # Eğer sağlık kontrolü başarılı ise 200 OK döndürün.
    return {"status": "ok"}

@app.post("/New_Token_Create/")
def New_Token_Request(data: Token_Create_Model):
    ho_pin = data.ho_pin
    ha_pin = data.ha_pin
    Token_Label = data.Token_Label
    SO_PIN = data.SO_PIN
    User_PIN = data.User_PIN
    message = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)
    return {"message:" : message}

@app.post("/verify_certificate_key/")
def verify_CRT(data: Verify_Certificate_Key_Model):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    CRT_Name = data.CRT_Name
    result = verify_certificate(CRT_Name, SlotID, SlotPIN, KeyName)
    return {"message:": result}
@app.post("/EC_Create/")
def ECCreate(data: EC_Create_Model):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    Key_Label = data.KeyLabel
    Curve = data.Algoritma
    result = EC_Create(SlotID,SlotPIN,Key_Label,Curve)
    if result:
        messages = "Created EC Key named "+str(Key_Label)
    else:
        messages = "Created EC Key named "+str(Key_Label)
    return {"message:": messages}

@app.post("/FileEncPYHSM")
def FileEncryption(data: FileEncDec):
    Slot_ID = data.ID
    Slot_PIN = data.PIN
    Init_Vector = data.init_vector
    Init_Vector_bytes = base64.b64decode(Init_Vector)
    KName = data.KName
    FNamePath = data.FNamePath
    result = encrypt_file(Slot_ID, Slot_PIN, FNamePath, KName, Init_Vector_bytes)
    return {"Message:": result}

@app.post("/FileDecPYHSM")
def FileDecryption(data: FileEncDec):
    Slot_ID = data.ID
    Slot_PIN = data.PIN
    Init_Vector = data.init_vector
    Init_Vector_bytes = base64.b64decode(Init_Vector)
    KName = data.KName
    FNamePath = data.FNamePath
    result = decrypt_file(Slot_ID, Slot_PIN, FNamePath, KName, Init_Vector_bytes)
    return {"Message:": result}

@app.post("/Slot_Find_PIN/")
def SlotFind(data: SlotPINFind_Model):
    API_Key = data.API_Key
    Action = data.Action
    Slot_PIN = data.Strings_Slot_PIN
    result = Slot_Find(API_Key,Action,Slot_PIN)
    return {"Message:": result}

@app.post("/Obje_Find_URL/")
def Obje_Url_finds(data: Obje_URL_Find):
    ID = data.ID
    PIN = data.PIN
    result = get_tokens(ID,PIN)
    data = json.loads(result)
    return data
@app.post("/HSM_Pool_Active/")
def HSM_Pool_Active(data: ActiveHSMModel):
    IP_address = data.IP_Address
    Port_address = data.Port_Address
    result = ConfigFileWrite(IP_address,Port_address)
    return {"message": result}

@app.post("/RSACreate/")
def RSACreate(data: RSA):
    Slot_ID = data.ID
    Slot_PIN = data.PIN
    KeyName = data.KName
    bits = data.BIT
    result = RSA_Create(Slot_ID,Slot_PIN,KeyName,bits)
    if result:
        messages = str(KeyName)+ " key was created"
    else:
        messages = str(KeyName)+ " key was not created"
    return {"message:": messages}

@app.post("/AESCreate/")
def AESCreate(data: AES):
    Slot_ID = data.SlotID
    Slot_PIN = data.SlotPIN
    KeyName = data.AES_KeyName
    bits = data.BIT
    result = AES_Creates(Slot_ID,Slot_PIN,KeyName,bits)
    if result:
        messages = str(KeyName)+ " key was created"
    else:
        messages = str(KeyName)+ " key was not created"
    return {"message:": messages}

@app.post("/CARequest/")
def CARequest(data: CARequest):
    ID = data.Slot_ID
    PIN = data.Slot_PIN
    PrivName = data.PrivateKeyName
    CommonName = data.CommonName
    OrganizationName = data.OrganizationName
    CountryName = data.CountryName
    CA_Files = CARequestCertificate(ID,PIN,PrivName,CommonName,OrganizationName,CountryName)
    return {"CA_Sertifikasi": CA_Files}

@app.post("/CARequestNew/")
def CARequest2_New(data: CARequest_New):
    ID = data.Slot_ID
    PIN = data.Slot_PIN
    PrivName = data.PrivateKeyName
    Days = data.Days
    Json_Data = data.data
    CA_Files = CARequestCertificate2(ID,PIN,PrivName,Days,Json_Data)
    return {"CA_Sertifikasi": CA_Files}

@app.post("/LoadCertificate/")
def LoadCertificate(data: CertificateLoad):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    CertificateFile = data.CertificateFile
    CertificateName = data.CertificateName
    result = Certificate_Load(SlotID,SlotPIN,CertificateFile,CertificateName)
    return result

# Dosyaların yükleneceği hedef dizini
UPLOAD_DIR = "/app/uploads/"

# Hedef dizini oluştur
if not os.path.exists(UPLOAD_DIR):
    os.makedirs(UPLOAD_DIR)

    
# @app.post("/CSR_To_CRT/")
# def upload_rsa_key_and_csr(rsa_key: UploadFile, csr_file: UploadFile, CompanyName: str = Form(...), pin: str = Form(...), slot_id: str = Form(...), ca_crt_name: str = Form(...), ca_key_name: str = Form(...)):
    
#     rsa_key_path = os.path.join(UPLOAD_DIR, rsa_key.filename)
#     with open(rsa_key_path, "wb") as rsa_key_dest:
#         rsa_key_dest.write(rsa_key.file.read())
#     csr_file_path = os.path.join(UPLOAD_DIR, csr_file.filename)
#     with open(csr_file_path, "wb") as csr_file_dest:
#         csr_file_dest.write(csr_file.file.read())
#     rsa_key_name = rsa_key.filename
#     csr_file_name = csr_file.filename
#     id = int(slot_id)
#     TypePrivate = "uploads"
#     private_key_data = Read_File_Func(TypePrivate,rsa_key_name)
#     CRT_Data = csr_t_crt(id,pin,csr_file_name,ca_crt_name,ca_key_name)
#     Insert_Certificate(CompanyName, CRT_Data, private_key_data)
#     return {"Sertifika Data ": CRT_Data}

file_directory = Path("/app/CRT")
@app.post("/download/")
async def download_file(file_name: str, file_type: str):
    if file_type == "Certificate":
        file_directory = Path("/app/CRT")
        file_path = file_directory / file_name
        if not file_path.is_file():
            return {"error": "File Not Found"}
    # Dosyanın yolu
    elif file_type == "Certification_Request":
        file_directory = Path("/app/CSR")
        file_path = file_directory / file_name
        if not file_path.is_file():
            return {"error": "File Not Found"}
    # file_path = 
    elif file_type == "CA_Certificate":
        file_directory = Path("/app/CA")
        file_path = file_directory / file_name
        if not file_path.is_file():
            return {"error": "File Not Found"}
    # Dosyanın varlığını kontrol edin
    else:
        return {"Message: ": "Specified Path not found"}

    # Dosyanın indirilmesi ve yanıt olarak döndürülmesi
    return FileResponse(file_path, headers={"Content-Disposition": f"attachment; filename={file_name}"})

@app.post("/UserCreate/")
async def CreateUser(data: UserData):
    slotID = data.SlotID
    SlotPIN = data.SlotPIN
    UserName = data.UserName
    Parola = data.Parola
    result = User_Obje_Create_Func(slotID,SlotPIN,UserName,Parola)
    return {"user Response": result}

@app.post("/UserVerify/")
async def VerifyUser(data: UserData):
    slotID = data.SlotID
    SlotPIN = data.SlotPIN
    UserName = data.UserName
    Parola = data.Parola
    result = User_Obje_Verifty_Func(slotID,SlotPIN,UserName,Parola)
    return {"user Response": result} 

@app.post("/UserObjeRemove/")
async def User_Destroy(Data: UserRemove):
    SlotID = Data.SlotID
    SlotPIN = Data.SlotPIN
    UserName = Data.UserName
    message = User_Delete(SlotID,SlotPIN,UserName)
    result = {"Message: ": message}
    return result

@app.post("/Certificate_Info_All/")
async def Certificate_Info(data: InfoCertificate):
    SlotID = data.ID
    SlotPin = data.PIN
    result = Cert_Info(SlotID,SlotPin)
    return result


@app.post("/User_Info_All/")
async def User_Info(data: InfoUser):
    SlotID = data.ID
    SlotPin = data.PIN
    result = User_Infos(SlotID,SlotPin)
    return result

@app.post("/Certificate_Info/")
async def Certificate_Info_Single(data: InfoCertificateSing):
    SlotID = data.ID
    SlotPin = data.PIN
    CertificateName = data.CertificateName
    result = Cert_InfoSing(SlotID,SlotPin,CertificateName)
    return result


@app.post("/CRT_Verifty/")
def verifty_crt(crt_file: UploadFile, CACertificateName: str = Form(...), pin: str = Form(...), slot_id: str = Form(...),):
    CRT_DIR = "/app/CRT"
    crt_path = os.path.join(CRT_DIR, crt_file.filename)
    with open(crt_path, "wb") as rsa_key_dest:
        rsa_key_dest.write(crt_file.file.read())
    crt_name = crt_file.filename
    id = int(slot_id)
    TypePrivate = "CRT"
    #crt_data = Read_File_Func(TypePrivate,crt_name)
    result = VeriftyCRT(id,pin,CACertificateName,crt_name)
    return {"Verifty ": result}

@app.post("/CRT_Verifty_Request/")
def verifty_crt_Request(data: verifty_crt_Request_model):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    CACRT2 = data.CA_CRT
    CRT_Name = data.CRT_Name

    #crt_data = Read_File_Func(TypePrivate,crt_name)
    result = VeriftyCRT(SlotID,SlotPIN,CACRT2,CRT_Name)
    return {"Verifty": result}

@app.post("/Create_JWT/")
def verifty_crt(crt_file: UploadFile, CACertificateName: str = Form(...), pin: str = Form(...), slot_id: str = Form(...),):
    CRT_DIR = "/app/CRT"
    crt_path = os.path.join(CRT_DIR, crt_file.filename)
    with open(crt_path, "wb") as rsa_key_dest:
        rsa_key_dest.write(crt_file.file.read())
    crt_name = crt_file.filename
    cert_name = crt_name.split('.')[0]
    id = int(slot_id)
    TFResult = VeriftyCRT(id,pin,CACertificateName,crt_name)
    if TFResult:
        result = create_jwt_token(cert_name)
        return_result = {"Token: ": result}
    else:
        result = "Certificate not verified"
        return_result = {"Error: ": result}
    return return_result


@app.post("/Verifty-JTW-Token/")
async def Verifty_Token(Data: Token):
    Token_STR = Data.tokens
    result = Verifty(Token_STR)
    return result

@app.post("/Obje_Remove/")
async def Obje_Destroy(Data: ObjeRemove):
    SlotID = Data.ID
    SlotPIN = Data.Slot_PIN
    ObjeType = Data.ObjeType
    ObjeLabel = Data.ObjeLabel
    message = RemoveObje(SlotID,SlotPIN,ObjeType,ObjeLabel)
    result = {"Message: ": message}
    return result

@app.post("/CSR_Request_HSM/")
async def CSR_HSMRequest(data: CSR_HSM_Request_Data):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    Country = data.Country
    City = data.City
    Company = data.Company
    Common_Name = data.Common_Name
    CompanyID = data.CompanyID
    result = CSR_Create(SlotID,SlotPIN,KeyName,Country,City,Company,Common_Name,CompanyID)
    return { "message:" : result}

@app.post("/CSR_Request_HSM_New/")
async def CSR_HSMRequest_New(data: CSR_HSM_Request_Data_New):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    Company = data.Company
    Json_Data = data.Json_Data
    result = CSR_Create_New(SlotID,SlotPIN,KeyName,Company,Json_Data)
    return { "message:" : result}



@app.post("/CSR_HSM_CRT/")
def CSRHSMCRT(csr_file: UploadFile, CompanyName: str = Form(...), pin: str = Form(...), slot_id: str = Form(...), ca_crt_name: str = Form(...), Days: int = Form(...), ca_key_name: str = Form(...)):

    csr_file_path = os.path.join(UPLOAD_DIR, csr_file.filename)
    with open(csr_file_path, "wb") as csr_file_dest:
        csr_file_dest.write(csr_file.file.read())

    csr_file_name = csr_file.filename
    id = int(slot_id)
    TypePrivate = "uploads"
    result = HSM_CSR(id,pin,ca_key_name,csr_file_name,ca_crt_name,Days)
    #Insert_Certificate(CompanyName, CRT_Data, private_key_data)
    return {"Message: ": result}

@app.post("/Two_Factör/")
def TwoFactörCreate(data: RandomChar):
    Slot_ID = data.SlotID
    Slot_PIN = data.SlotPIN
    Character = data.Character
    result = RandomCharacter(Slot_ID,Slot_PIN,Character)
    return result

@app.post("/AES_Data_Encryption/")
def AES_Encrypt(data: AESEnc_data):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    Data = data.Data
    init_Vector_str = data.init_Vector_str
    result = AESEncrypt(SlotID,SlotPIN,KeyName,Data,init_Vector_str)
    return result

# init_Vector_str = "4b04ae274cc4181cb2ee8ca9cdbb11d3"
@app.post("/AES_Data_Decryption/")
def AES_Decrypt(data: AESEnc_data):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    EncryptData = data.Data
    init_Vector_str = data.init_Vector_str
    result = AESDEcryption(SlotID,SlotPIN,KeyName,EncryptData,init_Vector_str)
    return result

@app.post("/PublicKeyExport/")
def ExpPublic(data: ExpPublic):
    slotID = data.SlotID
    SlotPIN = data.SlotPIN
    PublicKeyName =data.PublicKeyName
    result = PublicExport(slotID,SlotPIN,PublicKeyName)
    message = {"Message:": result}
    return message
@app.post("/CertificateExport/")
def ExpCertificate(data:ExportCert):
    SlotID = data.SlotID
    Certificate_Name = data.CertificateName
    result = CrtExport(SlotID,Certificate_Name)
    message = {"Message:": result}
    return message 

@app.post("/Check_Token_Slot/")
def TokenCheck(data:TokenN):
    TokenNames = data.TokenName
    result = Check_Token(TokenNames)
    message = {"Message: ": result}
    return message
    #return JSONResponse(content=message)

@app.post("/Label_Obje_Find/")
def Label_Find(data: FindLabelObje):
    Slot_ID = data.Slot_ID
    Slot_PIN = data.Slot_PIN
    Obje_Label = data.Obje_Label
    result = Find_Label_Obje(Slot_ID,Slot_PIN,Obje_Label)
    return {"message": result}

@app.post("/HSM_Tokens/")
def HSM_Tokens():
    result = Slot_Label_Func()
    return {"message": result}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)