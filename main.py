import pathlib
import getpass
import tkinter as tk
from tkinter import filedialog
from symmetric import encrypt_bytes, decrypt_bytes
from asymmetric import encrypt_for_recipient, decrypt_for_recipient, generate_or_load_rsa_keys
from signature import sign_file, verify_signature

BASE_DIR = pathlib.Path("data")
USER = input("Sender name: ")
SENDER_DIR = BASE_DIR / USER
SENDER_INBOX = SENDER_DIR / "inbox"
SENDER_OUTBOX = SENDER_DIR / "outbox"
SENDER_KEYS = SENDER_DIR / "keys"

for d in [SENDER_INBOX, SENDER_OUTBOX, SENDER_KEYS]:
    d.mkdir(parents=True, exist_ok=True)

def select_file(title="Select file", initial_dir=None):
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    file_path = filedialog.askopenfilename(title=title, initialdir=initial_dir)
    root.destroy()
    return file_path

def asymmetric_encrypt_workflow():
    recipient_name = input("Recipient name: ").strip()
    infile_path = select_file("Select file to encrypt for recipient", initial_dir=str(SENDER_INBOX))
    if not infile_path:
        print("[!] No file selected")
        return

    infile_path = pathlib.Path(infile_path)
    sender_priv, _ = generate_or_load_rsa_keys(SENDER_DIR, USER)
    recipient_dir = BASE_DIR / recipient_name
    recipient_dir.mkdir(parents=True, exist_ok=True)
    _, recipient_pub = generate_or_load_rsa_keys(recipient_dir, recipient_name)

    signature_bytes = sign_file(str(infile_path), str(sender_priv))
    encrypt_for_recipient(str(infile_path), recipient_pub, SENDER_OUTBOX, signature_bytes)

def asymmetric_decrypt_workflow():
    base = input("Base file name to decrypt: ").strip()
    recipient_name = input("Recipient name: ").strip()

    recipient_dir = BASE_DIR / recipient_name
    recipient_inbox = recipient_dir / "inbox"
    recipient_inbox.mkdir(parents=True, exist_ok=True)
    recipient_priv, _ = generate_or_load_rsa_keys(recipient_dir, recipient_name)

    signature = decrypt_for_recipient(base, recipient_priv, recipient_inbox, SENDER_OUTBOX)
    sender_name = input("Sender name: ").strip()
    sender_dir = BASE_DIR / sender_name
    _, sender_pub = generate_or_load_rsa_keys(sender_dir, sender_name)

    decrypted_file = recipient_inbox / f"dec_{base}"
    if verify_signature(str(decrypted_file), str(sender_pub), signature):
        print("[+] Signature verified!")
    else:
        print("❌ Signature verification failed!")

if __name__ == "__main__":
    print("=== Secure File Encryption System ===")
    mode = input("Encrypt or Decrypt? [e/d]: ").strip().lower()
    if mode == "e":
        asymmetric_encrypt_workflow()
    else:
        asymmetric_decrypt_workflow()
