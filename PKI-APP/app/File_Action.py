from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex
import os

def split_text_fixed_size(text, chunk_size):
    return [text[i:i+chunk_size] for i in range(0, len(text), chunk_size)]

HSM_Lib = "/lib64/libprocryptoki.so"
# Function to encrypt a file using AES-CBC mode with PKCS7 padding
def encrypt_file(SlotID, SlotPIN, file, aes_key_label, init_vector):
    try:
        file_root = "/opt/BackupLog/"
        file_path = str(file_root)+"/"+str(file)
        with open(file_path, 'rb') as file:
            cleartext = file.read()
            print(len(cleartext))
            chunk_size = 32700
            clear_dict = split_text_fixed_size(cleartext, chunk_size)
        dict_len = len(clear_dict)
        EndcryptText = b''
        for i in range(dict_len):
            with HsmClient(slot=SlotID, pin=SlotPIN, pkcs11_lib=HSM_Lib) as c:
                aes_handle = c.get_object_handle(label=aes_key_label)
                ciphertext = c.encrypt(handle=aes_handle,data=clear_dict[i],mechanism=HsmMech.AES_CBC_PAD,iv=init_vector)
                EndcryptText = EndcryptText + ciphertext
        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as file:
            file.write(EndcryptText)
        print("File encrypted successfully: " + encrypted_file_path)
        result = "İşlem Başarılı"
        return result
    except:
        print("Bir hata oluştu.")
        result = "İşlem Başarısız Oldu."
        return result


# Function to decrypt a file using AES-CBC mode with PKCS7 padding
def decrypt_file(SlotID, SlotPIN, encrypted_file, aes_key_label, init_vector):
    try:
        file_root = "/opt/BackupLog/"
        encrypted_file_path = str(file_root)+"/"+str(encrypted_file)
        with open(encrypted_file_path, 'rb') as file:
            ciphertext = file.read()
            chunk_size = 32704
            cipher_dict = split_text_fixed_size(ciphertext, chunk_size)
        cipher_len = len(cipher_dict)
        dec_plain = b''
        for i in range(cipher_len):
            with HsmClient(slot=SlotID, pin=SlotPIN, pkcs11_lib=HSM_Lib) as c:
                aes_handle = c.get_object_handle(label=aes_key_label)
                plaintext = c.decrypt(handle=aes_handle,data=cipher_dict[i],mechanism=HsmMech.AES_CBC_PAD,iv=init_vector)
                dec_plain = dec_plain + plaintext
        decrypted_file_path = encrypted_file_path[:-4]  # Remove the ".enc" extension
        with open(decrypted_file_path, 'wb') as file:
            file.write(dec_plain)
        print("File decrypted successfully: " + decrypted_file_path)
        result = "İşlem Başarılı"
        return result
    except:
        print("Bir hata oluştu.")
        result = "İşlem Başarısız Oldu."
        return result
