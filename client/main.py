import tkinter as tk
from tkinter import messagebox
from registration import register_user
from encryption import encrypt_file
from decryption import decrypt_file
from sign_and_forward import forward_package
import os

def main():
    root = tk.Tk()
    folder_for_title = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
    root.title(f"Secure Document Encryption System ({folder_for_title})")
    root.geometry("420x450")

    tk.Label(root, text="Sender / Action User:").pack()
    sender_entry = tk.Entry(root, width=30)
    sender_entry.pack()

    tk.Label(root, text="Receiver / Next Recipient:").pack()
    receiver_entry = tk.Entry(root, width=30)
    receiver_entry.pack()

    #REGISTER
    tk.Button(
        root,
        text="Register User",
        width=25,
        command=lambda: register_user(sender_entry.get())
    ).pack(pady=10)

    #ENCRYPT & SEND
    tk.Button(
        root,
        text="Encrypt & Send File",
        width=25,
        command=lambda: encrypt_file(
            sender_entry.get(),
            receiver_entry.get(),
            final_receiver_client_path="../shared"
        )
    ).pack(pady=5)

    #SIGN & FORWARD
    tk.Button(
        root,
        text="Sign & Forward Package",
        width=25,
        command=lambda: forward_package(
            sender_entry.get(),
            receiver_entry.get(),
            "../shared"
        )
    ).pack(pady=10)

    #DECRYPT
    tk.Label(root, text="Decrypter User:").pack()
    decrypter_entry = tk.Entry(root, width=30)
    decrypter_entry.pack()

    tk.Button(
        root,
        text="Decrypt File",
        width=25,
        command=lambda: decrypt_file(decrypter_entry.get())
    ).pack(pady=10)

    #EXIT BUTTON
    tk.Button(
        root,
        text="Exit",
        width=25,
        command=root.destroy
    ).pack(pady=10)

    root.mainloop()


if __name__ == "__main__":
    main()
