# Adnan Adib
# 1st August, 2024

import os as skibidi
import base64 as bs
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import padding

except ImportError:
    skibidi.system("pip install cryptography")


def generate_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt(encrypted_message: str, password: str) -> str:
    encrypted_data = bs.b64decode(encrypted_message)
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    encrypted_message = encrypted_data[32:]
    
    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    
    return decrypted.decode()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decryption.py <encrypted_message> <password>")
        sys.exit(1)
        
    encrypted_message = sys.argv[1]
    password = sys.argv[2]
    
    decrypted_message = decrypt(encrypted_message, password)
    print(f"Decrypted: {decrypted_message}")
