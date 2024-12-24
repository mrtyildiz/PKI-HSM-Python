import os

#### yüklemek için
## apt update
## apt install opensc

def Certificate_Load(ID,PIN,CerFile,CerName):
    SlotID = ID
    SlotPIN = PIN
    CRT_ROOT_DIR = "/app/CRT/"
    CertificateFile = str(CRT_ROOT_DIR)+CerFile
    
    CertificateName = CerName
    pkcs11_lib = os.environ.get('PYKCS11LIB')
    print(pkcs11_lib)
    Load_Certificate = 'pkcs11-tool --module '+str(pkcs11_lib)+' --slot '+str(SlotID)+' --login --pin '+str(SlotPIN)+' --write-object '+str(CertificateFile)+' --type cert --label "'+str(CertificateName)+'"'
    os.system(Load_Certificate)
    return True

#ID = 0
#PIN = "1111"
#CerFile = 'privCA.crt'
#CerName = 'privCAcrt'
#Certificate_Load(ID,PIN,CerFile,CerName)

