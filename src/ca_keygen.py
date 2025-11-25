# create_ca.py
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
import datetime
import os

os.makedirs("ca", exist_ok=True)

print("Creating CA keys and certificate (only once!)...")

# Generate CA key pair (4096-bit)
ca_key = RSA.generate(4096)

# Save CA keys
with open("ca/ca_private.pem", "wb") as f:
    f.write(ca_key.export_key())

with open("ca/ca_public.pem", "wb") as f:
    f.write(ca_key.publickey().export_key())

# Create simple self-signed CA cert
info = f"CN=MyProjectCA,O=DACS3101,ValidUntil=2035".encode()
hash_obj = SHA256.new(info)
signature = pkcs1_15.new(ca_key).sign(hash_obj)

with open("ca/ca_cert.pem", "w") as f:
    f.write("-----BEGIN CA CERTIFICATE-----\n")
    f.write(info.decode() + "\n")
    f.write(ca_key.publickey().export_key().decode())
    f.write("\nSignature: " + signature.hex())
    f.write("\n-----END CA CERTIFICATE-----\n")

print("CA created successfully in ./ca/")
print("Never delete or regenerate this!")