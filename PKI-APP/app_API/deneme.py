from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from Get_Private_Key import Private_Key


def CRT_Key_Vertify(Slot_ID,Slot_PIN,KeyName):
    private_key = Private_Key(Slot_ID,Slot_PIN,KeyName)
    #private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    #private_key_modulus = private_key.private_numbers().n
    modulus = private_key.key.public_numbers().n
    print(modulus)

# Slot = 0
# pin = "1111"
# Key = "RSAKeyspriv"
# CRT_Key_Vertify(Slot,pin,Key)


from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta  # Import the datetime module

# Set the validity period (in days)
validity_days = 365  # Adjust this as needed

# Calculate the not_valid_before and not_valid_after dates
not_valid_before = datetime.utcnow()
not_valid_after = not_valid_before + timedelta(days=validity_days)

# Create the subject for the CSR
subject = x509.Name([
    x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "Counter"),
    x509.NameAttribute(x509.NameOID.LOCALITY_NAME, "City"),
    x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Company"),
    x509.NameAttribute(x509.NameOID.COMMON_NAME, "Common_Name"),
    x509.NameAttribute(x509.NameOID.SERIAL_NUMBER, "id")
])

# Create the CSR with validity period
csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
    private_key, hashes.SHA256(), default_backend()
).not_valid_before(not_valid_before).not_valid_after(not_valid_after)

# Set the CSR file name
CSR_Files = "Company.csr"

# Write the CSR to a file
with open(CSR_Files, "wb") as csr_file:
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    csr_file.write(csr_pem)

result = str(ROOT_DIR_CSR) + "/" + str(CSR_Files)
