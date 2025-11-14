# Usage:
#   python main.py encrypt   -> asks for file name (in data/in) and passphrase, then encrypts
#   python main.py decrypt   -> asks for base file name and passphrase (repeats until correct), then decrypts
#
# Output layout (flat):
#   data/out/<filename>.package.json
#   data/out/<filename>.payload.bin
#   data/out/<filename>   (decrypted result)

import sys
import pathlib
import getpass
from symmetric import encrypt_bytes, decrypt_bytes
from packaging import write_package, read_package

ALGO    = "AES-256-GCM"
IN_DIR  = pathlib.Path("data/in")
OUT_DIR = pathlib.Path("data/out")

def encrypt():
    """Encrypt one file from data/in/ into data/out/"""
    name = input("File name in data/in (e.g. a.txt): ").strip()
    src = IN_DIR / name
    if not src.is_file():
        print(f"[!] File not found: {src}")
        return

    pw = getpass.getpass("Passphrase: ")
    data = src.read_bytes()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    enc = encrypt_bytes(data, pw)
    write_package(str(OUT_DIR), src.name, ALGO, enc.salt, enc.iv, enc.tag, enc.ciphertext)
    print(f"[+] Encrypted -> {OUT_DIR / (src.name + '.package.json')}, {OUT_DIR / (src.name + '.payload.bin')}")

def decrypt():
    """Decrypt one file from data/out/ back to its original form"""
    base = input("Base file name to decrypt (e.g. a.txt): ").strip()

    # keep asking until correct passphrase
    while True:
        pw = getpass.getpass("Passphrase: ")
        try:
            m, salt, iv, tag, ct, orig = read_package(str(OUT_DIR), base)
            pt = decrypt_bytes(salt, iv, ct, tag, pw)
            out_path = OUT_DIR / orig
            out_path.write_bytes(pt)
            print(f"[+] Decrypted -> {out_path}")
            break

        except ValueError:
            # PyCryptodome raises ValueError if MAC/tag check fails (wrong passphrase)
            print("❌ Wrong passphrase. Please try again.\n")

        except FileNotFoundError as e:
            print(f"[!] Package not found for '{base}': {e}")
            return

        except Exception as e:
            print(f"[!] Error while decrypting '{base}': {e}")
            return

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in {"encrypt", "decrypt"}:
        print("Usage:\n  python main.py encrypt\n  python main.py decrypt")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "encrypt":
        encrypt()
    else:
        decrypt()
