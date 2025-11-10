from __future__ import annotations
import os
from dataclasses import dataclass
from typing import Optional
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Parameters
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1
KEY_LEN, SALT_LEN, IV_LEN, TAG_LEN = 32, 16, 12, 16  # AES-256-GCM

@dataclass
class EncResult:
    salt: bytes
    iv: bytes
    ciphertext: bytes
    tag: bytes

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))

def encrypt_bytes(plaintext: bytes, passphrase: str, aad: Optional[bytes]=None) -> EncResult:
    salt, iv = os.urandom(SALT_LEN), os.urandom(IV_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    ct_full = aes.encrypt(iv, plaintext, aad)  # ciphertext||tag (last 16 bytes = GCM tag)
    return EncResult(salt, iv, ct_full[:-TAG_LEN], ct_full[-TAG_LEN:])

def decrypt_bytes(salt: bytes, iv: bytes, ciphertext: bytes, tag: bytes,
                  passphrase: str, aad: Optional[bytes]=None) -> bytes:
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    return aes.decrypt(iv, ciphertext + tag, aad)
