
import sys
from asymmetric import ensure_rsa_keys, encrypt_file, decrypt_file

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"encrypt", "decrypt"}:
        print("Usage:\n  python main.py encrypt\n  python main.py decrypt")
        return

    mode = sys.argv[1]

    if mode == "encrypt":
        input_file = input("Enter file path to encrypt: ").strip()
        user_name = input("Recipient username: ").strip()
        _, pub_key = ensure_rsa_keys(user_name)
        encrypt_file(input_file, pub_key)

    else:
        base_file = input("Enter base filename to decrypt: ").strip()
        user_name = input("Your username: ").strip()
        priv_key, _ = ensure_rsa_keys(user_name)
        decrypt_file(base_file, priv_key)

if __name__ == "__main__":
    main()

