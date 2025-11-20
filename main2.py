# main.py
import pathlib
import tkinter as tk
from tkinter import filedialog
from pathlib import Path

from symmetric import encrypt_bytes, decrypt_bytes
from asymmetric import encrypt_for_recipient, decrypt_for_recipient, generate_or_load_rsa_keys
from signature import sign_file, verify_signature

BASE_DIR = pathlib.Path("data")

def ensure_user_folders(user: str) -> dict:
    """Create and return important paths for a user."""
    user_dir = BASE_DIR / user
    inbox = user_dir / "inbox"
    outbox = user_dir / "outbox"
    keys = user_dir / "keys"
    for d in (inbox, outbox, keys):
        d.mkdir(parents=True, exist_ok=True)
    return {"user_dir": user_dir, "inbox": inbox, "outbox": outbox, "keys": keys}

def choose_file(initial_dir: Path = None, title: str = "Select file"):
    """Open a file picker and return the chosen path or None."""
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(title=title, initialdir=str(initial_dir) if initial_dir else None)
    root.destroy()
    return path

def asymmetric_encrypt_workflow(sender: str):
    sender_paths = ensure_user_folders(sender)
    recipient = input("Recipient name: ").strip()
    recipient_paths = ensure_user_folders(recipient)

    # Ask user to choose a file from sender's inbox (or anywhere)
    print("Please choose file to encrypt (file dialog will open)...")
    chosen = choose_file(initial_dir=sender_paths["inbox"], title="Select file to encrypt")
    if not chosen:
        print("[!] No file selected. Aborting.")
        return

    # Ensure RSA keys exist (generate if missing)
    sender_priv, sender_pub = generate_or_load_rsa_keys(sender_paths["user_dir"], sender)
    # For recipient, generate or load keys; we need recipient public key path
    recipient_priv, recipient_pub = generate_or_load_rsa_keys(recipient_paths["user_dir"], recipient)

    # Sign the plaintext
    try:
        signature_bytes = sign_file(chosen, str(sender_priv))
    except Exception as e:
        print(f"[!] Error signing file: {e}")
        return

    # Encrypt for recipient (this writes package + key to sender outbox)
    try:
        encrypt_for_recipient(chosen, recipient_pub, sender_paths["outbox"], signature_bytes)
        print(f"[+] Encrypted package saved to: {sender_paths['outbox']}")
    except Exception as e:
        print(f"[!] Error encrypting for recipient: {e}")

def asymmetric_decrypt_workflow():
    base = input("Base file name to decrypt (example: a.txt): ").strip()
    recipient = input("Recipient name: ").strip()
    sender = input("Sender name (to verify signature): ").strip()

    recipient_paths = ensure_user_folders(recipient)
    sender_paths = ensure_user_folders(sender)

    # Ensure recipient private key exists
    recipient_priv, recipient_pub = generate_or_load_rsa_keys(recipient_paths["user_dir"], recipient)
    # Ensure sender public key exists (used to verify signature)
    s_priv, s_pub = generate_or_load_rsa_keys(sender_paths["user_dir"], sender)

    try:
        # Decrypt for recipient; source_dir is where sender placed outbox packages
        signature = decrypt_for_recipient(base, recipient_priv, recipient_paths["inbox"], sender_paths["outbox"])
    except FileNotFoundError as e:
        print(f"[!] Missing files: {e}")
        return
    except Exception as e:
        print(f"[!] Error during decryption: {e}")
        return

    # Verify the returned signature against the decrypted file
    decrypted_file = recipient_paths["inbox"] / f"dec_{base}"
    if not decrypted_file.exists():
        print(f"[!] Decrypted file not found at {decrypted_file}")
        return

    try:
        ok = verify_signature(str(decrypted_file), str(s_pub), signature)
    except Exception as e:
        print(f"[!] Error verifying signature: {e}")
        return

    if ok:
        print("[+] Signature verified: file is authentic and unmodified.")
        print(f"[+] Decrypted file available at: {decrypted_file}")
    else:
        print("❌ Signature verification FAILED! Do not trust this file.")

def main():
    print("=== Secure File Encryption System ===")
    actor = input("Are you Sender or Receiver? [s/r]: ").strip().lower()
    if actor not in {"s", "r"}:
        print("Invalid choice. Exiting.")
        return

    if actor == "s":
        sender_name = input("Sender name: ").strip()
        if not sender_name:
            print("Provide a sender name. Exiting.")
            return
        asymmetric_encrypt_workflow(sender_name)
    else:
        asymmetric_decrypt_workflow()

if __name__ == "__main__":
    main()
