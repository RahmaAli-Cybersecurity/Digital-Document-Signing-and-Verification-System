import os

USER_DIR = "users/"
SENT_DIR = "sent/"
RECEIVED_DIR = "received/"

def ensure_dirs():
    for d in [USER_DIR, SENT_DIR, RECEIVED_DIR]:
        os.makedirs(d, exist_ok=True)
