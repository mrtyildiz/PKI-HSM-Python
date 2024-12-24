from pyhsm.hsmclient import HsmClient
import os

### RSA Anahtar oluşturma işlemi
def RSA_Create(Slot_ID,Slot_PIN,KeyName,BIT):
   HSM_SO_File = os.environ.get('PYKCS11LIB')
   # with HsmClient(slot=Slot_ID, pin=Slot_PIN, pkcs11_lib=HSM_SO_File) as c:
   #    PubKeyName = KeyName+"pub"
   #    PriKeyName = KeyName+"priv"
   #    key_handles = c.create_rsa_key_pair(public_key_label=PubKeyName,
   #                                        private_key_label=PriKeyName,
   #                                        key_length=2048,
   #                                        public_exponent=b"\x01\x00\x01",
   #                                        token=True,
   #                                        modifiable=False,
   #                                        extractable=True,
   #                                        sign_verify=True,
   #                                        encrypt_decrypt=True,
   #                                        wrap_unwrap=True,
   #                                        derive=False)
   #    print(dir(key_handles))
   #    print("public_handle: " + str(key_handles[0]))
   #    print("private_handle: " + str(key_handles[1]))
   try:
    with HsmClient(slot=Slot_ID, pin=Slot_PIN, pkcs11_lib=HSM_SO_File) as c:
         PubKeyName = KeyName+"pub"
         PriKeyName = KeyName+"priv"
         # BIT = 512,1024,2048,3072,4096
         key_handles = c.create_rsa_key_pair(public_key_label=PubKeyName,
                                          private_key_label=PriKeyName,
                                          key_length=BIT,
                                          public_exponent=b"\x01\x00\x01",
                                          token=True,
                                          modifiable=False,
                                          extractable=True,
                                          sign_verify=True,
                                          encrypt_decrypt=True,
                                          sensitive=False,
                                          wrap_unwrap=True,
                                          derive=False)
         print(dir(key_handles))
         print("public_handle: " + str(key_handles[0]))
         print("private_handle: " + str(key_handles[1]))

         # message = "RSA Key Oluşturuldu"

   except Exception as e:
        print(f"An error occurred: {e}")
        if 'CKR_DEVICE_ERROR (0x00000030)' in str(e):
            return True
        else:
            return False
   else:
      return True
    
     

# ID = 2
# PIN ="1111"
# KName = "dene2"
# BIT = 2048
# a = RSA_Create(ID,PIN,KName,BIT)
# print(a)