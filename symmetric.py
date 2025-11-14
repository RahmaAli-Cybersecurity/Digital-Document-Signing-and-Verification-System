import os
from dataclasses import dataclass
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

KEY_LEN = 32    
SALT_LEN = 16
IV_LEN   = 12    
TAG_LEN  = 16

@dataclass
class EncResult:
    salt: bytes
    iv: bytes
    ciphertext: bytes
    tag: bytes

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    return scrypt(
        passphrase.encode("utf-8"),
        salt=salt,
        key_len=KEY_LEN,
        N=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )

def encrypt_bytes(plaintext, key_or_pass, is_passphrase=True):
    if is_passphrase:
        salt = os.urandom(SALT_LEN)
        key = _derive_key(key_or_pass, salt)
    else:
        salt = b""
        key = key_or_pass

    iv = os.urandom(IV_LEN)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=TAG_LEN)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return EncResult(
        salt=salt,
        iv=iv,
        ciphertext=ciphertext,
        tag=tag
    )

def decrypt_bytes(salt, iv, ciphertext, tag, key_or_pass, is_passphrase=True):

    if is_passphrase:
        key = _derive_key(key_or_pass, salt)
    else:
        key = key_or_pass

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv, mac_len=TAG_LEN)
    return cipher.decrypt_and_verify(ciphertext, tag)  # raises ValueError if wrong tag

