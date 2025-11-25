from Crypto.PublicKey import RSA
from tkinter import messagebox
import os
from ca_client import ca_request
from utils import USER_DIR, ensure_dirs

ensure_dirs()

def register_user(username):
    if username.strip() == "":
        messagebox.showerror("Error", "Enter username")
        return

    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key().decode()

    #SAVE PRIVATE KEY 
    user_path = f"{USER_DIR}{username}/"
    os.makedirs(user_path, exist_ok=True)
    with open(f"{user_path}private.pem", "wb") as f:
        f.write(private_key)

    #STORE PUBLIC KEY AT THE CA
    reply = ca_request({"action": "register", "username": username, "public_key": public_key})
    if "error" in reply:
        messagebox.showerror("Error", reply["error"])
    else:
        messagebox.showinfo("Success", f"User '{username}' registered!")
