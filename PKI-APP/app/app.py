from pydantic import BaseModel
from fastapi import FastAPI, UploadFile, Form, HTTPException, File, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
import os
import json
import base64
from pathlib import Path
app = FastAPI()
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

#### Lib Load
from Slot_Intialized_Merge import Token_Create
from Verify_Action import verify_certificate
from Key_Action import EC_Create, RSA_Create, AES_Creates
from File_Action import encrypt_file, decrypt_file
from Slot_PIN_Action import Slot_Find
from HSM_Action import ConfigFileWrite
from Certificate_Loads import Certificate_Load
from Certificate_Info_Single import Cert_InfoSing
from Certificate_Action import Cert_Info, VeriftyCRT, CSR_Create_New
from CA_Certificate_Request2 import CARequestCertificate2
from User_Action import User_Obje_Create_Func, User_Obje_Verifty_Func, User_Delete, User_Infos
from Obje_Action import RemoveObje
from Action import AESEncrypt, AESDEcryption, PublicExport, CrtExport, Check_Token, Slot_Label_Func
from Find_Label_Priv import Find_Label_Obje
from CSR_HSM_CRT import HSM_CSR
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
    if not verify_license():
        # Lisans kontrolü başarısız olursa, bir hata sayfası döndür
        content = "<html><body><h1>Lisans Hatası</h1><p>Lisansınız geçersiz veya süresi dolmuş.</p></body></html>"
        return HTMLResponse(content=content, status_code=403)

    response = await call_next(request)
    return response
# Eğer sağlık kontrolü başarılı ise 200 OK döndürün.
@app.get("/health", status_code=200)
async def health_check():
    return {"status": "ok"}
### Token Create Model
class Token_Create_Model(BaseModel):
    ho_pin: str
    ha_pin: str
    Token_Label: str
    SO_PIN: str
    User_PIN:str
## Token Create 
@app.post("/New_Token_Create/")
def New_Token_Request(data: Token_Create_Model):
    ho_pin = data.ho_pin
    ha_pin = data.ha_pin
    Token_Label = data.Token_Label
    SO_PIN = data.SO_PIN
    User_PIN = data.User_PIN
    message = Token_Create(ho_pin,ha_pin,Token_Label,SO_PIN,User_PIN)
    return {"message:" : message}

## Sertifika Key Doğrulama
class Verify_Certificate_Key_Model(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    CRT_Name: str
@app.post("/verify_certificate_key/")
def verify_CRT(data: Verify_Certificate_Key_Model):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    CRT_Name = data.CRT_Name
    result = verify_certificate(CRT_Name, SlotID, SlotPIN, KeyName)
    return {"message:": result}

### EC Key Create
class EC_Create_Model(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyLabel: str
    Algoritma: str

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

###File Encrypt Decrypt
class FileEncDec(BaseModel):
    ID: int
    PIN: str
    init_vector: str
    KName: str
    FNamePath: str

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

class SlotPINFind_Model(BaseModel):
    API_Key: str
    Action: str
    Strings_Slot_PIN: str

@app.post("/Slot_Find_PIN/")
def SlotFind(data: SlotPINFind_Model):
    API_Key = data.API_Key
    Action = data.Action
    Slot_PIN = data.Strings_Slot_PIN
    result = Slot_Find(API_Key,Action,Slot_PIN)
    return {"Message:": result}

class ActiveHSMModel(BaseModel):
    IP_Address: str
    Port_Address: str

@app.post("/HSM_Pool_Active/")
def HSM_Pool_Active(data: ActiveHSMModel):
    IP_address = data.IP_Address
    Port_address = data.Port_Address
    result = ConfigFileWrite(IP_address,Port_address)
    return {"message": result}

class RSA(BaseModel):
    ID: int
    PIN: str
    KName: str
    BIT: int

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

class AES(BaseModel):
    SlotID: int
    SlotPIN: str
    AES_KeyName: str
    BIT: int


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

class CARequest_New(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    PrivateKeyName: str
    Days: int
    data: str

@app.post("/CARequestNew/")
def CARequest2_New(data: CARequest_New):
    ID = data.Slot_ID
    PIN = data.Slot_PIN
    PrivName = data.PrivateKeyName
    Days = data.Days
    Json_Data = data.data
    CA_Files = CARequestCertificate2(ID,PIN,PrivName,Days,Json_Data)
    return {"CA_Sertifikasi": CA_Files}

class CertificateLoad(BaseModel):
    SlotID: int
    SlotPIN: str
    CertificateFile: str
    CertificateName: str

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


class UserData(BaseModel):
    SlotID: int
    SlotPIN: str
    UserName: str
    Parola: str

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

class UserRemove(BaseModel):
    SlotID: int
    SlotPIN: str
    UserName: str

@app.post("/UserObjeRemove/")
async def User_Destroy(Data: UserRemove):
    SlotID = Data.SlotID
    SlotPIN = Data.SlotPIN
    UserName = Data.UserName
    message = User_Delete(SlotID,SlotPIN,UserName)
    result = {"Message: ": message}
    return result

class InfoCertificate(BaseModel):
    ID: int
    PIN: str

@app.post("/Certificate_Info_All/")
async def Certificate_Info(data: InfoCertificate):
    SlotID = data.ID
    SlotPin = data.PIN
    
    result = Cert_Info(SlotID,SlotPin)
    return result

class InfoUser(BaseModel):
    ID: int
    PIN: str

@app.post("/User_Info_All/")
async def User_Info(data: InfoUser):
    SlotID = data.ID
    SlotPin = data.PIN
    result = User_Infos(SlotID,SlotPin)
    return result

class InfoCertificateSing(BaseModel):
    ID: int
    PIN: str
    CertificateName: str

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

class verifty_crt_Request_model(BaseModel):
    SlotID: int
    SlotPIN: str
    CA_CRT: str
    CRT_Name: str
@app.post("/CRT_Verifty_Request/")
def verifty_crt_Request(data: verifty_crt_Request_model):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    CACRT2 = data.CA_CRT
    CRT_Name = data.CRT_Name
    result = VeriftyCRT(SlotID,SlotPIN,CACRT2,CRT_Name)
    return {"Verifty": result}

class ObjeRemove(BaseModel):
    ID: int
    Slot_PIN: str
    ObjeType: str
    ObjeLabel: str
@app.post("/Obje_Remove/")
async def Obje_Destroy(Data: ObjeRemove):
    SlotID = Data.ID
    SlotPIN = Data.Slot_PIN
    ObjeType = Data.ObjeType
    ObjeLabel = Data.ObjeLabel
    message = RemoveObje(SlotID,SlotPIN,ObjeType,ObjeLabel)
    result = {"Message: ": message}
    return result

class CSR_HSM_Request_Data_New(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    Company: str
    Json_Data: str

@app.post("/CSR_Request_HSM_New/")
async def CSR_HSMRequest_New(data: CSR_HSM_Request_Data_New):
    SlotID = data.SlotID
    SlotPIN = data.SlotPIN
    KeyName = data.KeyName
    Company = data.Company
    Json_Data = data.Json_Data
    result = CSR_Create_New(SlotID,SlotPIN,KeyName,Company,Json_Data)
    return { "message:" : result}

class AESEnc_data(BaseModel):
    SlotID: int
    SlotPIN: str
    KeyName: str
    Data: str
    init_Vector_str: str

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

class ExpPublic(BaseModel):
    SlotID: int
    SlotPIN: str
    PublicKeyName: str
@app.post("/PublicKeyExport/")
def ExpPublic(data: ExpPublic):
    slotID = data.SlotID
    SlotPIN = data.SlotPIN
    PublicKeyName =data.PublicKeyName
    result = PublicExport(slotID,SlotPIN,PublicKeyName)
    message = {"Message:": result}
    return message

class ExportCert(BaseModel):
    SlotID: int
    CertificateName: str
@app.post("/CertificateExport/")
def ExpCertificate(data:ExportCert):
    SlotID = data.SlotID
    Certificate_Name = data.CertificateName
    result = CrtExport(SlotID,Certificate_Name)
    message = {"Message:": result}
    return message
 
class TokenN(BaseModel):
    TokenName: str
@app.post("/Check_Token_Slot/")
def TokenCheck(data:TokenN):
    TokenNames = data.TokenName
    result = Check_Token(TokenNames)
    message = {"Message: ": result}
    return message

class FindLabelObje(BaseModel):
    Slot_ID: int
    Slot_PIN: str
    Obje_Label: str
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
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)