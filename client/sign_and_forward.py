import os
import shutil
import json
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from ca_client import ca_request
from utils import USER_DIR

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def forward_package(forwarder_username, next_recipient_username, next_recipient_client_path):

    if forwarder_username.strip() == "" or next_recipient_username.strip() == "":
        messagebox.showerror("Error", "Enter both forwarder and next recipient names.")
        return

    #SELECT PACKAGE
    filepath = filedialog.askopenfilename(
        filetypes=[("Package Files", "*.pkg")],
        title="Select Package to Forward",
        initialdir=os.path.join(BASE_DIR, "received")
    )
    if not filepath:
        return

    #LOAD PACKAGE
    try:
        with open(filepath, "r") as f:
            package = json.load(f)
    except:
        messagebox.showerror("Error", "Invalid package file")
        return

    #LOAD FORWARDER PRIVATE KEY
    try:
        forwarder_priv_path = os.path.join(BASE_DIR, USER_DIR, forwarder_username, "private.pem")
        with open(forwarder_priv_path, "rb") as f:
            forwarder_priv = RSA.import_key(f.read())
    except:
        messagebox.showerror("Error", "Forwarder key not found")
        return

    #SIGN CURRENT CHAIN
    chain_bytes = json.dumps(package["signature_chain"], sort_keys=True).encode()
    chain_hash = SHA256.new(chain_bytes)
    signature = pkcs1_15.new(forwarder_priv).sign(chain_hash)

    #Append new chain entry
    package["signature_chain"].append({
        "signer": forwarder_username,
        "sig": signature.hex(),
        "type": "chain-sign"
    })

    #SAVE NEW PACKAGE
    sender_sent_dir = os.path.join(BASE_DIR, "sent")
    os.makedirs(sender_sent_dir, exist_ok=True)

    new_pkg_name = os.path.basename(filepath).replace(".pkg", "") + f"_via_{forwarder_username}.pkg"
    new_pkg_path = os.path.join(sender_sent_dir, new_pkg_name)

    with open(new_pkg_path, "w") as f:
        json.dump(package, f)

    #FORWARD TO NEXT RECIPIENT
    if next_recipient_client_path:
        receiver_received_dir = os.path.join(next_recipient_client_path, "received")
        os.makedirs(receiver_received_dir, exist_ok=True)
        shutil.copy(new_pkg_path, os.path.join(receiver_received_dir, new_pkg_name))

    messagebox.showinfo("Success", f"Package signed by {forwarder_username} and forwarded to {next_recipient_username}")
