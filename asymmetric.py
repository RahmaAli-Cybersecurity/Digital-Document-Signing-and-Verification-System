import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from symmetric import encrypt_bytes, decrypt_bytes
from packaging import write_package, read_package

def generate_or_load_rsa_keys(user_dir: Path, user_name: str):
    keys_dir = user_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path = keys_dir / f"{user_name}_priv.pem"
    pub_path = keys_dir / f"{user_name}_pub.pem"

    if not (priv_path.exists() and pub_path.exists()):
        key = RSA.generate(2048)
        priv_path.write_bytes(key.export_key())
        pub_path.write_bytes(key.publickey().export_key())
        print(f"[+] Generated new RSA key pair for {user_name}")
    else:
        print(f"[+] Loaded existing RSA key pair for {user_name}")

    return priv_path, pub_path

def ensure_file_exists(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

def encrypt_for_recipient(input_file: str, recipient_pub_path: Path, out_dir: Path, signature_bytes: bytes):
    pubkey = RSA.import_key(recipient_pub_path.read_bytes())
    cipher_rsa = PKCS1_OAEP.new(pubkey)

    aes_key = os.urandom(32)
    plaintext = Path(input_file).read_bytes()
    enc = encrypt_bytes(plaintext, aes_key, is_passphrase=False)

    base = Path(input_file).name
    write_package(out_dir, base, "AES-256-GCM", enc.salt, enc.iv, enc.tag, enc.ciphertext, signature_bytes)

    key_path = out_dir / f"{base}.key.bin"
    key_path.write_bytes(cipher_rsa.encrypt(aes_key))

    print(f"[+] Encrypted data: {base}")
    print(f"[+] Encrypted AES key: {key_path}")

def decrypt_for_recipient(base_filename: str, recipient_priv_path: Path, dest_dir: Path, source_dir: Path):
    privkey = RSA.import_key(recipient_priv_path.read_bytes())
    cipher_rsa = PKCS1_OAEP.new(privkey)

    key_path = source_dir / f"{base_filename}.key.bin"
    ensure_file_exists(key_path)
    aes_key = cipher_rsa.decrypt(key_path.read_bytes())

    manifest, salt, iv, tag, ct, signature = read_package(source_dir, base_filename)
    pt = decrypt_bytes(salt, iv, ct, tag, aes_key, is_passphrase=False)

    dest_dir.mkdir(parents=True, exist_ok=True)
    out_path = dest_dir / f"dec_{base_filename}"
    out_path.write_bytes(pt)
    print(f"[+] File decrypted -> {out_path}")

    return signature
