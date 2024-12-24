from PyKCS11 import *
from asn1crypto.keys import ECDomainParameters, NamedCurve

def EC_Create(Slot_ID, Slot_PIN, label, Algoritma):
    try:
        # Initialize PyKCS11 library
        pkcs11 = PyKCS11Lib()
        pkcs11.load()

        # Get the specified slot
        slot = pkcs11.getSlotList(tokenPresent=True)[Slot_ID]

        # Open a session and login
        session = pkcs11.openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION)
        session.login(Slot_PIN)

        # Map algorithm names to curve values
        curve_map = {
            'ansiX9p192r1': "1.2.840.10045.3.1.1",
            'ansiX9p256r1': "1.2.840.10045.3.1.7",
            'ansiX9p384r1': "1.3.132.0.34",
            'brainpoolP192r1': "1.3.36.3.3.2.8.1.1.1",
            'brainpoolP224r1': "1.3.36.3.3.2.8.1.1.2",
            'brainpoolP256r1': "1.3.36.3.3.2.8.1.1.4",
            'nistp192': "1.2.840.10045.3.1.1",
            'nistp224': "1.3.132.0.33",
            'nistp521': "1.3.132.0.35",
            'prime192v1': "1.2.840.10045.3.1.1",
            'prime192v2': "1.2.840.10045.3.1.2",
            'prime192v3': "1.2.840.10045.3.1.3",
            'prime256v1': "1.2.840.10045.3.1.7",
            'prime384v1': "1.3.132.0.34"
        }

        # Get the curve value based on the specified algorithm
        curve = curve_map.get(Algoritma, Algoritma)

        # Setup the domain parameters
        domain_params = ECDomainParameters(name="named", value=NamedCurve(curve))
        ec_params = domain_params.dump()

        # Define templates for public and private keys
        ec_public_tmpl = [
            (CKA_CLASS, CKO_PUBLIC_KEY),
            (CKA_PRIVATE, CK_FALSE),
            (CKA_TOKEN, CK_TRUE),
            (CKA_ENCRYPT, CK_TRUE),
            (CKA_VERIFY, CK_TRUE),
            (CKA_WRAP, CK_TRUE),
            (CKA_KEY_TYPE, CKK_ECDSA),
            (CKA_EC_PARAMS, ec_params),
            (CKA_LABEL, label),
        ]

        ec_priv_tmpl = [
            (CKA_CLASS, CKO_PRIVATE_KEY),
            (CKA_KEY_TYPE, CKK_ECDSA),
            (CKA_TOKEN, CK_TRUE),
            (CKA_DECRYPT, CK_TRUE),
            (CKA_SIGN, CK_TRUE),
            (CKA_UNWRAP, CK_TRUE),
            (CKA_SENSITIVE, CK_FALSE),  # CKA_SENSITIVE değeri eklenmiştir
            (CKA_LABEL, label),
        ]

        # Generate key pair
        (pub_key, priv_key) = session.generateKeyPair(
            ec_public_tmpl, ec_priv_tmpl, mecha=PyKCS11.MechanismECGENERATEKEYPAIR
        )

        # Logout and close the session
        session.logout()
        session.closeSession()

        result = f'Created EC Key named {label}'
    except PyKCS11Error as e:
        result = f'Error: {e}'
    except Exception as e:
        result = f'EC Key named {label} could not be generated. Error: {e}'
    return result

# Example usage
Slot_ID = 1
Slot_PIN = "1111"
label = "DenemeEC3"
Algoritma = "ansiX9p192r1"
print(EC_Create(Slot_ID, Slot_PIN, label, Algoritma))
