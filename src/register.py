# keys + certificate

from Crypto.PublicKey import RSA
import socket
import os
import sys

def main():
    print("=" * 50)
    print("           User Registration & Certificate")
    print("=" * 50)

    # Ask for name
    while True:
        name = input("\nEnter your name (e.g., Alice, Bob, Sara): ").strip()
        if name and name.replace(" ", "").isalpha():
            USER_NAME = name.capitalize()
            break
        print("Please enter a valid name (letters only).")

    user_dir = f"users/{USER_NAME.lower()}"
    os.makedirs(user_dir, exist_ok=True)

    priv_path = f"{user_dir}/{USER_NAME.lower()}_private.pem"
    pub_path = f"{user_dir}/{USER_NAME.lower()}_public.pem"
    cert_path = f"{user_dir}/{USER_NAME.lower()}_cert.pem"

    # Generate key pair (only if not already done)
    if not os.path.exists(priv_path):
        print(f"\nGenerating 2048-bit RSA key pair for {USER_NAME}...")
        key = RSA.generate(2048)
        with open(priv_path, "wb") as f:
            f.write(key.export_key())
        with open(pub_path, "wb") as f:
            f.write(key.publickey().export_key())
        print("Key pair generated and saved securely.")
    else:
        print(f"Keys already exist for {USER_NAME}. Reusing them.")

    # Read public key
    pubkey_pem = open(pub_path, "r").read()

    # Request certificate from CA
    print(f"\nConnecting to Certificate Authority (CA) on port 9999...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect(("127.0.0.1", 9999))
            request = f"{USER_NAME}|||{pubkey_pem}"
            s.sendall(request.encode())

            print("Request sent. Waiting for signed certificate...")
            cert_data = s.recv(16384).decode('utf-8', errors='ignore')

        if "ERROR" in cert_data.upper() or "-----BEGIN CERTIFICATE-----" not in cert_data:
            print("Failed to get certificate!")
            print("Response:", cert_data[:200])
            sys.exit(1)

        # Save certificate
        with open(cert_path, "w") as f:
            f.write(cert_data)

        print("\nSUCCESS!")
        print(f"{USER_NAME} is now fully registered!")
        print(f"   Private Key → {priv_path}")
        print(f"   Public Key  → {pub_path}")
        print(f"   Certificate → {cert_path}")
        print("\nYou can now sign and encrypt documents!")

    except ConnectionRefusedError:
        print("\nCannot connect to CA Server!")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)

    print("\n" + "=" * 50)

if __name__ == "__main__":
    main()