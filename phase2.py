
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from packaging import write_package, read_package

KEY_FOLDER = "keys"
OUT_DIR = "data/out"

def ensure_rsa_keys(user_name: str, key_size: int = 2048):
    """Generate or load RSA key pair for a user"""
    os.makedirs(KEY_FOLDER, exist_ok=True)
    priv_path = os.path.join(KEY_FOLDER, f"{user_name}_private.pem")
    pub_path = os.path.join(KEY_FOLDER, f"{user_name}_public.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        return priv_path, pub_path

    key = RSA.generate(key_size)
    with open(priv_path, "wb") as f:
        f.write(key.export_key())
    with open(pub_path, "wb") as f:
        f.write(key.publickey().export_key())
    return priv_path, pub_path

def encrypt_file(input_file: str, recipient_public_key_file: str):
    """Encrypt file using fresh AES key, wrap AES key with recipient's RSA public key"""
    recipient_key = RSA.import_key(open(recipient_public_key_file, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    session_key = os.urandom(16)  # AES-128 key
    cipher_aes = AES.new(session_key, AES.MODE_CBC)
    
    with open(input_file, "rb") as f:
        plaintext = f.read()
    ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

    enc_session_key = cipher_rsa.encrypt(session_key)

    # Use Phase 1 packaging
    os.makedirs(OUT_DIR, exist_ok=True)
    write_package(
        OUT_DIR,
        os.path.basename(input_file),
        algorithm="AES-128-CBC+RSA",
        salt=enc_session_key,
        iv=cipher_aes.iv,
        tag=b"",
        ciphertext=ciphertext
    )
    print(f"[+] File encrypted -> {OUT_DIR}/{os.path.basename(input_file)}.package.json")

def decrypt_file(base_filename: str, recipient_private_key_file: str):
    """Decrypt file: unwrap AES key using RSA private key, then AES decrypt"""
    private_key = RSA.import_key(open(recipient_private_key_file, "rb").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    m, enc_session_key, iv, tag, ciphertext, orig = read_package(OUT_DIR, base_filename)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    out_path = os.path.join(OUT_DIR, orig)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print(f"[+] File decrypted -> {out_path}")

