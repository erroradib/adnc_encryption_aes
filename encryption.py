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

def encrypt(message: str, password: str) -> str:

    salt = skibidi.urandom(16)
    key = generate_key(password, salt)
    iv = skibidi.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()
    
    encrypted = encryptor.update(padded_data) + encryptor.finalize()
    
    return bs.b64encode(salt + iv + encrypted).decode()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python encryption.py <message> <password>")
        sys.exit(1)

    message = sys.argv[1]
    password = sys.argv[2]
    
    encrypted_message = encrypt(message, password)
    print(f"Encrypted: {encrypted_message}")
