# ca_server.py
# FINAL CLEAN VERSION – NO REVOCATION – WORKS WITH YOUR EXISTING CA KEY

import socket
import os
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from datetime import datetime

HOST = "127.0.0.1"
PORT = 9999

# === Folders ===
os.makedirs("users", exist_ok=True)
os.makedirs("issued_certs", exist_ok=True)

# === Load existing CA private key (YOU ALREADY HAVE THIS) ===
CA_PRIVATE_PATH = "ca/ca_private.pem"

if not os.path.exists(CA_PRIVATE_PATH):
    print("ERROR: ca/ca_private.pem not found!")
    print("Make sure your CA key is in the 'ca' folder")
    exit(1)

ca_key = RSA.import_key(open(CA_PRIVATE_PATH, "rb").read())
print("CA private key loaded successfully from ca/ca_private.pem")

# === Load all previously issued certificates ===
ISSUED_CERTS = {}  # serial → full cert text

for filename in os.listdir("issued_certs"):
    if filename.endswith("_cert.pem"):
        path = f"issued_certs/{filename}"
        cert = open(path).read()
        try:
            serial = [l for l in cert.splitlines() if l.startswith("Serial:")][0].split()[1]
            ISSUED_CERTS[serial] = cert
        except:
            pass

print(f"Loaded {len(ISSUED_CERTS)} existing certificates from issued_certs/")

# === Issue new certificate ===
def issue_certificate(user_id: str, pubkey_pem: str):
    user_id = user_id.strip().capitalize()
    serial = str(len(ISSUED_CERTS) + 1)

    user_pub = RSA.import_key(pubkey_pem.encode())
    tbs = f"Serial:{serial} Subject:CN={user_id} Issuer:CN=DACS3101-CA".encode() + user_pub.export_key()
    signature = pkcs1_15.new(ca_key).sign(SHA256.new(tbs))

    cert = f"""-----BEGIN CERTIFICATE-----
Serial: {serial}
Subject: CN={user_id}
Issuer: CN=DACS3101-CA
Valid From: {datetime.now().strftime('%Y-%m-%d')}
Valid Until: 2030-12-31
-----BEGIN PUBLIC KEY-----
{user_pub.export_key().decode()}
-----END PUBLIC KEY-----
Signature: {signature.hex()}
-----END CERTIFICATE-----"""

    # Save to user's folder
    user_dir = f"users/{user_id.lower()}"
    os.makedirs(user_dir, exist_ok=True)
    with open(f"{user_dir}/{user_id.lower()}_cert.pem", "w") as f:
        f.write(cert)

    # Save to public directory
    with open(f"issued_certs/{user_id.lower()}_cert.pem", "w") as f:
        f.write(cert)

    ISSUED_CERTS[serial] = cert
    print(f"Certificate issued → {user_id} (Serial {serial})")
    return cert.encode()

# === Validate certificate ===
def validate_certificate(cert_text: str):
    try:
        serial = [l for l in cert_text.splitlines() if l.startswith("Serial:")][0].split()[1]
        if serial in ISSUED_CERTS and ISSUED_CERTS[serial].strip() == cert_text.strip():
            return "VALID"
        else:
            return "TAMPERED OR UNKNOWN"
    except:
        return "INVALID FORMAT"

# === Server ===
print("=" * 60)
print("DACS3101 CA SERVER READY (NO REVOCATION)")
print(f"Listening on {HOST}:{PORT}")
print("Waiting for registration & validation requests...")
print("=" * 60)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen()

    while True:
        conn, addr = s.accept()
        with conn:
            data = conn.recv(32768).decode('utf-8', errors='ignore').strip()

            if "|||" in data:  # Registration request
                user_id, pubkey = data.split("|||", 1)
                cert = issue_certificate(user_id, pubkey)
                conn.sendall(cert)

            elif data.startswith("VALIDATE|||"):  # Validation request
                cert = data[len("VALIDATE|||"):]
                result = validate_certificate(cert)
                conn.sendall(result.encode())

            else:
                conn.sendall(b"UNKNOWN COMMAND")