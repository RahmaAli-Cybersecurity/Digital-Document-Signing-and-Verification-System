import pathlib
import getpass
import tkinter as tk
from tkinter import filedialog
from symmetric import encrypt_bytes, decrypt_bytes
from packaging import write_package, read_package
from asymmetric import (
    encrypt_for_recipient,
    decrypt_for_recipient,
    generate_or_load_rsa_keys,
    ensure_file_exists
)

IN_DIR  = pathlib.Path("data/in")
OUT_DIR = pathlib.Path("data/out")


# -----------------------------
# Tkinter file selector
# -----------------------------

def select_file(title="Select file"):
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True) 
    file_path = filedialog.askopenfilename(title=title)
    root.destroy()
    return file_path


# -----------------------------
# Symmetric (Phase 1)
# -----------------------------

def symmetric_encrypt():
    file_path = select_file("Select file to encrypt")
    if not file_path:
        print("[!] No file selected")
        return

    src = pathlib.Path(file_path)
    if not src.is_file():
        print(f"[!] File not found: {src}")
        return

    pw = getpass.getpass("Passphrase: ")
    data = src.read_bytes()

    enc = encrypt_bytes(data, pw, is_passphrase=True)
    write_package(str(OUT_DIR), src.name, "AES-256-GCM", enc.salt, enc.iv, enc.tag, enc.ciphertext)
    print(f"[+] Symmetric encrypted file written: {OUT_DIR / src.name}.package.json / .payload.bin")


def symmetric_decrypt():
    file_path = select_file("Select file to decrypt")
    if not file_path:
        print("[!] No file selected")
        return

    base = pathlib.Path(file_path).name
    while True:
        pw = getpass.getpass("Passphrase: ")
        try:
            m, salt, iv, tag, ct, orig = read_package(str(OUT_DIR), base)
            pt = decrypt_bytes(salt, iv, ct, tag, pw, is_passphrase=True)
            out_path = OUT_DIR / ("dec_" + orig)
            out_path.write_bytes(pt)
            print(f"[+] File decrypted -> {out_path}")
            break
        except Exception as e:
            print(f"Wrong passphrase or error: {e}")


# -----------------------------
# Per-recipient (Phase 2)
# -----------------------------

def asymmetric_encrypt_workflow():
    name = input("Recipient name: ").strip()
    file_path = select_file("Select file to encrypt for recipient")
    if not file_path:
        print("[!] No file selected")
        return

    infile_path = file_path
    ensure_file_exists(infile_path)
    priv_path, pub_path = generate_or_load_rsa_keys(name)
    encrypt_for_recipient(str(infile_path), pub_path)


def asymmetric_decrypt_workflow():
    base = input("Base file name to decrypt: ").strip()
    name = input("Recipient name: ").strip()
    priv_path = f"{OUT_DIR}/{name}_priv.pem"
    ensure_file_exists(priv_path)
    decrypt_for_recipient(base, priv_path)


# -----------------------------
# Main CLI
# -----------------------------

if __name__ == "__main__":
    print("=== Secure File Encryption System ===\n")
    mode = input("Encrypt or Decrypt? [e/d]: ").strip().lower()
    if mode == "e":
        workflow = input("Use symmetric or per-recipient encryption? [s/p]: ").strip().lower()
        if workflow == "s":
            symmetric_encrypt()
        else:
            asymmetric_encrypt_workflow()
    else:
        workflow = input("Decrypt symmetric or recipient-protected file? [s/p]: ").strip().lower()
        if workflow == "s":
            symmetric_decrypt()
        else:
            asymmetric_decrypt_workflow()

