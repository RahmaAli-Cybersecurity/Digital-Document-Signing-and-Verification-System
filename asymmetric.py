import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from packaging import write_package, read_package
from symmetric import encrypt_bytes, decrypt_bytes

OUT_DIR = "data/out"

def generate_or_load_rsa_keys(user_name: str):
    priv_path = os.path.join(OUT_DIR, f"{user_name}_priv.pem")
    pub_path  = os.path.join(OUT_DIR, f"{user_name}_pub.pem")
    
    if not (os.path.exists(priv_path) and os.path.exists(pub_path)):
        key = RSA.generate(2048)
        os.makedirs(OUT_DIR, exist_ok=True)
        with open(priv_path, "wb") as f: f.write(key.export_key())
        with open(pub_path, "wb") as f: f.write(key.publickey().export_key())
    return priv_path, pub_path

def ensure_file_exists(path):
    if not os.path.exists(path):
        raise FileNotFoundError(f"File not found: {path}")

def encrypt_for_recipient(input_file, recipient_public_key_path):
    pubkey = RSA.import_key(open(recipient_public_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(pubkey)

    aes_key = os.urandom(32)

    plaintext = open(input_file, "rb").read()
    enc = encrypt_bytes(plaintext, aes_key, is_passphrase=False)

    enc_aes_key = cipher_rsa.encrypt(aes_key)

    base = os.path.basename(input_file)
    os.makedirs(OUT_DIR, exist_ok=True)
    write_package(OUT_DIR, base, "AES-256-GCM", enc.salt, enc.iv, enc.tag, enc.ciphertext)

    key_path = os.path.join(OUT_DIR, base + ".key.bin")
    with open(key_path, "wb") as f: f.write(enc_aes_key)

    print(f"[+] Encrypted data: {base}")
    print(f"[+] Encrypted AES key: {key_path}")

def decrypt_for_recipient(base_filename, recipient_private_key_path):
    privkey = RSA.import_key(open(recipient_private_key_path, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(privkey)

    key_path = os.path.join(OUT_DIR, base_filename + ".key.bin")
    aes_key = cipher_rsa.decrypt(open(key_path, "rb").read())

    m, salt, iv, tag, ct, orig = read_package(OUT_DIR, base_filename)
    pt = decrypt_bytes(salt, iv, ct, tag, aes_key, is_passphrase=False)

    out_path = os.path.join(OUT_DIR, "dec_" + orig)
    with open(out_path, "wb") as f: f.write(pt)
    print(f"[+] File decrypted -> {out_path}")
