from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from  Get_Private_Key import Private_Key
import os
from datetime import datetime, timedelta  # Import the datetime module

from cryptography.hazmat.backends import default_backend
  # Import the datetime module
def Array_Create(array):
    if os.path.exists(array):
        pass
    else:
        os.mkdir(array)

def CSR_Create_New(slot,pin,KeyName,Company,Json_Data):
    Data = Json_Data.split('#')
    name_attributes = []
    # Remove the last element from the list
    Data.pop()

    name_attributes = []

    for item in Data:
        try:
            name_attribute = eval(item)
            name_attributes.append(name_attribute)
            subject_attributes = [eval(attribute_str) for attribute_str in Data]    
            ROOT_DIR_CSR = "/app/CSR"
            if os.path.exists(ROOT_DIR_CSR):
                pass
            else:
                os.mkdir(ROOT_DIR_CSR)
            os.chdir(ROOT_DIR_CSR)
            
            #Private Keyin Çekilmesi 
            private_key = Private_Key(slot,pin,KeyName)
            if private_key == False:
                result = "Key Not Found"
            else:
                # CSR altında kullanılacak konu bilgilerini oluşturun
                subject = x509.Name(subject_attributes)

                # Create the CSR with validity period
            
                # # CSR oluşturun
                csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
                    private_key, hashes.SHA256()
                )
                CSR_Files = Company+".csr"

                # CSR'i bir dosyaya yazın (örneğin, csr.pem)
                with open(CSR_Files, "wb") as csr_file:
                    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
                    csr_file.write(csr_pem)
                result = str(ROOT_DIR_CSR) +"/"+ str(CSR_Files)
                result2 = "/app"+str(result)
            return result2
        except Exception as e:
            result = f"Error:{str(e)}"
            print(result)
            return result


# Slot = 1
# slot_pin = "1111"
# CA_KeyName = "Clientprivss"
# Counter = "TR"
# City = "Ankara"
# Company = "HiyTech"
# Common_Name = "HiyTech.com"
# id = "18188181818"

# CSR_Create(Slot,slot_pin,CA_KeyName,Counter,City,Company,Common_Name,id)