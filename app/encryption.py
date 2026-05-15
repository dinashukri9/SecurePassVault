import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher

ph = PasswordHasher()

def hash_master_password(password):
    return ph.hash(password)

def verify_master_password(hashed, password):
    try:
        return ph.verify(hashed, password)
    except:
        return False

def generate_key(master_password: str, salt: bytes) -> bytes:
    import hashlib
    key = hashlib.pbkdf2_hmac('sha256', master_password.encode(), salt, 100000)
    return key[:32]

def encrypt_password(plain_password: str, master_password: str) -> str:
    salt = os.urandom(16)
    key = generate_key(master_password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(plain_password.encode()) + encryptor.finalize()
    result = base64.b64encode(salt + iv + encrypted).decode('utf-8')
    return result

def decrypt_password(encrypted_password: str, master_password: str) -> str:
    try:
        data = base64.b64decode(encrypted_password.encode('utf-8'))
        salt = data[:16]
        iv = data[16:32]
        encrypted = data[32:]
        key = generate_key(master_password, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted) + decryptor.finalize()
        return decrypted.decode('utf-8')
    except:
        return None