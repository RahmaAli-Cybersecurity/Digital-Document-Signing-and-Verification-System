import os
import json
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from ca_client import ca_request
from utils import USER_DIR, RECEIVED_DIR, ensure_dirs

ensure_dirs()


def decrypt_file(receiver_username):

    receiver_username = receiver_username.strip()
    if receiver_username == "":
        messagebox.showerror("Error", "Enter decrypter (receiver) username")
        return

    base_dir = os.path.dirname(os.path.abspath(__file__))
    shared_received_dir = os.path.join(os.path.dirname(base_dir), "shared", "received")
    local_received_dir = RECEIVED_DIR

    if os.path.isdir(shared_received_dir):
        initial_dir = shared_received_dir
    else:
        initial_dir = local_received_dir

    filepath = filedialog.askopenfilename(
        filetypes=[("Package Files", "*.pkg"), ("All files", "*.*")],
        initialdir=initial_dir,
        title="Select encrypted package"
    )
    if not filepath:
        return

    #LOAD RECIEVER PRIVATE KEY
    try:
        with open(f"{USER_DIR}{receiver_username}/private.pem", "rb") as f:
            private_key = RSA.import_key(f.read())
    except Exception:
        messagebox.showerror("Error", f"Receiver '{receiver_username}' not registered locally.")
        return

    #LOAD PACKAGE JSON
    try:
        with open(filepath, "r") as f:
            package = json.load(f)
    except Exception:
        messagebox.showerror("Error", "Invalid package file.")
        return

    #
    #AES FILE DECRYPTION
    #

    try:
        enc_key = bytes.fromhex(package["enc_key"])
        nonce = bytes.fromhex(package["nonce"])
        tag = bytes.fromhex(package["tag"])
        ciphertext = bytes.fromhex(package["ciphertext"])

        rsa_cipher = PKCS1_OAEP.new(private_key)
        aes_key = rsa_cipher.decrypt(enc_key)  # Only final receiver can decrypt this key

        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)

    except Exception as e:
        messagebox.showerror("Decryption Error",
                             f"File is NOT intended for '{receiver_username}' or is corrupted.\n\n{e}")
        return

    #
    #SIGNATURE CHAIN VERIFICATION
    #
    chain = package.get("signature_chain", [])
    chain_results = []
    all_valid = True

    #Helper for ordering of signature chain serialization
    def canonical(obj):
        return json.dumps(obj, sort_keys=True).encode()

    #ORIGIN SIGNATURE (file-origin)
    origin = chain[0]
    origin_user = origin["signer"]

    #Recompute hash of plaintext
    computed_hash = SHA256.new(plaintext).hexdigest()

    if computed_hash != origin["hash_hex"]:
        chain_results.append(f"INVALID ORIGIN HASH for {origin_user}")
        all_valid = False
    else:
        pub = ca_request({"action": "get_key", "username": origin_user})
        pub_key = RSA.import_key(pub["public_key"].encode())

        digest = SHA256.new(plaintext)

        try:
            pkcs1_15.new(pub_key).verify(digest, bytes.fromhex(origin["sig"]))
            chain_results.append(f"VALID ORIGIN SIGNATURE: {origin_user}")
        except:
            chain_results.append(f"INVALID ORIGIN SIGNATURE: {origin_user}")
            all_valid = False

    #FORWARDER SIGNATURES
    prev_chain = [origin]

    for entry in chain[1:]:
        signer = entry["signer"]

        pub = ca_request({"action": "get_key", "username": signer})
        pub_key = RSA.import_key(pub["public_key"].encode())

        prev_bytes = canonical(prev_chain)
        prev_hash = SHA256.new(prev_bytes)

        try:
            pkcs1_15.new(pub_key).verify(prev_hash, bytes.fromhex(entry["sig"]))
            chain_results.append(f"VALID CHAIN SIGNATURE: {signer}")
        except:
            chain_results.append(f"INVALID CHAIN SIGNATURE: {signer}")
            all_valid = False

        prev_chain.append(entry)

    # 
    # SAVE DECRYPTED FILE
    # 
    os.makedirs(RECEIVED_DIR, exist_ok=True)
    out_filename = os.path.basename(filepath).replace(".pkg", "")
    out_path = f"{RECEIVED_DIR}{out_filename}"

    with open(out_path, "wb") as f:
        f.write(plaintext)

    # 
    #FINAL POPUP MESSAGE
    # 
    popup_msg = "SIGNATURE CHAIN RESULTS:\n\n" + "\n".join(chain_results)
    popup_msg += f"\n\nDecrypted file saved to:\n{out_path}"

    if all_valid:
        messagebox.showinfo("Decryption & Verification Success", popup_msg)
    else:
        messagebox.showwarning("Decryption Completed (Chain Issues)", popup_msg)
