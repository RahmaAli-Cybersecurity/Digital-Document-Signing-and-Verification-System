import os
import shutil
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import json
from ca_client import ca_request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def encrypt_file(sender_username, final_receiver_username, final_receiver_client_path=None):

    if sender_username.strip() == "" or final_receiver_username.strip() == "":
        messagebox.showerror("Error", "Enter both sender and receiver names")
        return

    file_path = filedialog.askopenfilename(
        title="Select File to Encrypt",
        initialdir=os.path.join(os.path.dirname(BASE_DIR), "shared")
    )
    if not file_path:
        return

    #LOAD SENDER PRIVATE KEY
    try:
        priv_key_path = os.path.join(BASE_DIR, "users", sender_username, "private.pem")
        with open(priv_key_path, "rb") as f:
            private_key = RSA.import_key(f.read())
    except FileNotFoundError:
        messagebox.showerror("Error", f"Sender '{sender_username}' not registered locally.")
        return

    #GET FINAL RECEIVER PUBLIC KEY 
    reply = ca_request({"action": "get_key", "username": final_receiver_username})
    if "error" in reply:
        messagebox.showerror("Error", f"Receiver '{final_receiver_username}' not found on CA.")
        return

    final_pub = RSA.import_key(reply["public_key"].encode())

    #READ FILE AND HASH 
    with open(file_path, "rb") as f:
        plaintext = f.read()

    file_hash = SHA256.new(plaintext)

    #SIGN FILE HASH (Start of Signature Chain) 
    signature = pkcs1_15.new(private_key).sign(file_hash)

    signature_chain = [{
        "signer": sender_username,
        "sig": signature.hex(),
        "hash_hex": file_hash.hexdigest(),
        "type": "file-origin"
    }]

    #AES ENCRYPTION 
    aes_key = get_random_bytes(32)
    cipher = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    #RSA ENCRYPT AES KEY (E2EE) 
    cipher_rsa = PKCS1_OAEP.new(final_pub)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    #PACKAGE 
    package = {
        "ciphertext": ciphertext.hex(),
        "enc_key": enc_aes_key.hex(),
        "nonce": cipher.nonce.hex(),
        "tag": tag.hex(),
        "signature_chain": signature_chain,
        "sender": sender_username,
        "final_receiver": final_receiver_username
    }

    #SAVE & SEND 
    sender_sent_dir = os.path.join(BASE_DIR, "sent")
    os.makedirs(sender_sent_dir, exist_ok=True)

    package_name = os.path.basename(file_path) + ".pkg"
    sender_package_path = os.path.join(sender_sent_dir, package_name)

    with open(sender_package_path, "w") as f:
        json.dump(package, f)

    #Copy to final receiver inbox
    if final_receiver_client_path:
        receiver_received_dir = os.path.join(final_receiver_client_path, "received")
        os.makedirs(receiver_received_dir, exist_ok=True)
        try:
            shutil.copy(sender_package_path, os.path.join(receiver_received_dir, package_name))
        except FileNotFoundError:
            messagebox.showwarning("Warning", "Receiver path not found. File saved locally only.")
            return

    messagebox.showinfo("Success", f"Secure E2E package sent to {final_receiver_username}")
