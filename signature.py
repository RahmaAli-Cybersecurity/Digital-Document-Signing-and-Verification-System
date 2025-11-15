from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from pathlib import Path

def sign_file(file_path: str, priv_key_path: str) -> bytes:
    file_path = Path(file_path)
    priv_key_path = Path(priv_key_path)

    data = file_path.read_bytes()
    privkey = RSA.import_key(priv_key_path.read_bytes())
    h = SHA256.new(data)
    signature = pkcs1_15.new(privkey).sign(h)
    return signature

def verify_signature(file_path: str, pub_key_path: str, signature: bytes) -> bool:
    data = Path(file_path).read_bytes()
    pubkey = RSA.import_key(Path(pub_key_path).read_bytes())
    h = SHA256.new(data)
    try:
        pkcs1_15.new(pubkey).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
