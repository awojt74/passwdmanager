import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

def encrypt_password(password):
    if isinstance(password, str):
        password = password.encode()

    key = os.urandom(32)  
    iv = os.urandom(16)   

    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(password) + padder.finalize()

    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded_data) + encryptor.finalize()
    
    return ct, key, iv

def decrypt_password(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    return data.decode()


ct, key, iv = encrypt_password(input("Podaj hasło do zaszyfrowania: "))
print("Zaszyfrowane hasło (hex):", ct.hex())

original = decrypt_password(ct, key, iv)
print("Odszyfrowane hasło:", original)
