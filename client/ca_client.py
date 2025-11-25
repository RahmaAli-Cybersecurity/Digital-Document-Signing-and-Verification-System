import socket
import json

CA_HOST = "127.0.0.1"
CA_PORT = 5000

def ca_request(data):
    sock = socket.socket()
    sock.connect((CA_HOST, CA_PORT))
    sock.send(json.dumps(data).encode())
    reply = sock.recv(8192).decode()
    sock.close()
    return json.loads(reply)
