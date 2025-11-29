
import base64, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# AES via Fernet for simplicity (uses AES-128 in CBC with HMAC under the hood)
def _ensure_key(key: bytes=None):
    if key:
        if isinstance(key, str):
            key = key.encode()
        return base64.urlsafe_b64encode(key.ljust(32, b'0')[:32])
    return Fernet.generate_key()

def aes_encrypt(plaintext: bytes, key=None):
    k = _ensure_key(key)
    f = Fernet(k)
    token = f.encrypt(plaintext)
    return token.decode()

def aes_decrypt(token: str, key=None):
    k = _ensure_key(key)
    f = Fernet(k)
    return f.decrypt(token.encode())

def rsa_generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub = private_key.public_key()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem

def rsa_encrypt(pub_pem: bytes, plaintext: bytes):
    pub = serialization.load_pem_public_key(pub_pem)
    ct = pub.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return base64.b64encode(ct).decode()

def rsa_decrypt(priv_pem: bytes, token: str):
    from cryptography.hazmat.primitives import serialization
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    ct = base64.b64decode(token)
    pt = private_key.decrypt(ct, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
    return pt
