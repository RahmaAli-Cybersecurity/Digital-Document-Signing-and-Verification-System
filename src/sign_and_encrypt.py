# src/sign_and_encrypt.py
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import os
import json
import base64

def sign_and_encrypt():
    print("SIGN & ENCRYPT DOCUMENT TOOL")
    print("=" * 50)

    # 1. Choose sender
    sender = input("Your name (e.g., Alice): ").strip().capitalize()
    sender_dir = f"../users/{sender.lower()}"

    if not os.path.exists(f"{sender_dir}/{sender.lower()}_private.pem"):
        print("Sender not registered!")
        return

    # 2. Choose recipient
    recipient = input("Recipient name (e.g., Bob): ").strip().capitalize()
    recip_dir = f"../users/{recipient.lower()}"
    recip_cert_path = f"{recip_dir}/{recipient.lower()}_cert.pem"
    if not os.path.exists(recip_cert_path):
        print("Recipient not registered or has no certificate!")
        return

    # 3. Choose file
    doc_path = input("Document to send (e.g., ../documents/contract.pdf): ").strip()
    if not os.path.exists(doc_path):
        print("File not found!")
        return

    print("\nProcessing...")

    # Load sender private key
    priv_key = RSA.import_key(open(f"{sender_dir}/{sender.lower()}_private.pem", "rb").read())
    signer = pkcs1_15.new(priv_key)

    # Load recipient public key from certificate
    cert_text = open(recip_cert_path, "r").read()
    start = cert_text.find("-----BEGIN PUBLIC KEY-----")
    end = cert_text.find("-----END PUBLIC KEY-----")
    pubkey_pem = cert_text[start:end+24]
    recip_pub_key = RSA.import_key(pubkey_pem)

    # Read document
    data = open(doc_path, "rb").read()

    # 1. Compute hash + sign
    h = SHA256.new(data)
    signature = signer.sign(h)

    # 2. Generate AES session key
    aes_key = get_random_bytes(32)  # 256-bit

    # 3. Encrypt document with AES
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ct_bytes = cipher_aes.encrypt(pad(data, AES.block_size))

    # 4. Encrypt AES key with recipient's public key
    cipher_rsa = PKCS1_OAEP.new(recip_pub_key)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # 5. Package everything
    package = {
        "sender": sender,
        "recipient": recipient,
        "filename": os.path.basename(doc_path),
        "iv": base64.b64encode(cipher_aes.iv).decode(),
        "encrypted_aes_key": base64.b64encode(enc_aes_key).decode(),
        "encrypted_document": base64.b64encode(ct_bytes).decode(),
        "signature": base64.b64encode(signature).decode(),
        "sender_cert": open(f"{sender_dir}/{sender.lower()}_cert.pem", "r").read()
    }

    # Save as .secured file
    output_file = f"../received/{sender}_to_{recipient}_{os.path.basename(doc_path)}.secured"
    with open(output_file, "w") as f:
        json.dump(package, f, indent=2)

    print(f"\nSUCCESS! Secure package created:")
    print(f"   → {output_file}")
    print(f"   → Send this file to {recipient}")

if __name__ == "__main__":
    sign_and_encrypt()