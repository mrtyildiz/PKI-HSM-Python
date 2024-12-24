from PyKCS11 import *
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
import os
def generate_ec_key_pair(session, label, curve='secp256r1'):
    pub_template = [
        (CKA_TOKEN, True),
        (CKA_PRIVATE, False),
        (CKA_LABEL, label),
        (CKA_VERIFY, True),
        (CKA_EC_PARAMS, bytes.fromhex(curve)),
    ]
 
    priv_template = [
        (CKA_TOKEN, True),
        (CKA_PRIVATE, True),
        (CKA_LABEL, label),
        (CKA_SENSITIVE, True),
        (CKA_SIGN, True),
        (CKA_EC_PARAMS, bytes.fromhex(curve)),
    ]
 
    pub_key, priv_key = session.generateKeyPair(
        CKM_EC_KEY_PAIR_GEN,
        {
            CKA_LABEL: label,
        },
        pub_template,
        priv_template
    )
 
    return pub_key, priv_key
 
def sign_ecdsa(session, private_key, data):
    mech = (CKM_ECDSA, CKF_SIGN)
    session.login("1111")  # Replace with your PIN
 
    # Initialize signing mechanism
    session.signInit(mech, private_key)
 
    # Sign the data
    signature = session.sign(data)
 
    session.logout()
    return signature
 
def verify_ecdsa(public_key, data, signature):
    verifier = DSS.new(public_key, 'fips-186-3')
    h = SHA256.new(data)
 
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False
 
def main():
    lib = os.environ.get('HSM_SO_File')
    pkcs11 = PyKCS11Lib()
    pkcs11.load(lib)
 
    slot = pkcs11.getSlotList()[2]
    session = pkcs11.openSession(slot)
 
    label = "ECC_PRIV"
    pub_key, priv_key = generate_ec_key_pair(session, label)
 
    data_to_sign = b"Hello, world!"
 
    signature = sign_ecdsa(session, priv_key, data_to_sign)
 
    # Verify the signature
    public_key = ECC.construct(curve='secp256r1', point_x=pub_key[CKA_EC_POINT][:32],
                               point_y=pub_key[CKA_EC_POINT][32:])
    if verify_ecdsa(public_key, data_to_sign, signature):
        print("ECDSA Signature is valid.")
    else:
        print("ECDSA Signature is invalid.")
 
    session.closeSession()
 
if __name__ == "__main__":
    main()
