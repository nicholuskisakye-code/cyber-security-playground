
import bcrypt, hashlib, base64

def hash_password_bcrypt(password: str):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def verify_password_bcrypt(password: str, hashed: bytes):
    return bcrypt.checkpw(password.encode(), hashed)

def sha256_hash(text: str):
    h = hashlib.sha256()
    h.update(text.encode())
    return h.hexdigest()
