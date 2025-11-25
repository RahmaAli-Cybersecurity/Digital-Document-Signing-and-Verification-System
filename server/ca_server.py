import socket, json, os, threading

CA_DB = "ca_db.json"
HOST = "127.0.0.1"
PORT = 5000

#Load/Save CA Database
def load_ca():
    if not os.path.exists(CA_DB):
        with open(CA_DB, "w") as f:
            json.dump({}, f)
    with open(CA_DB, "r") as f:
        return json.load(f)

def save_ca(ca):
    with open(CA_DB, "w") as f:
        json.dump(ca, f, indent=4)

#Client connection
def handle_client(conn, addr):
    try:
        data = conn.recv(8192).decode()
        request = json.loads(data)
        ca = load_ca()

        if request["action"] == "register":
            user = request["username"]
            if user in ca:
                conn.send(json.dumps({"error": "User already exists"}).encode())
            else:
                ca[user] = request["public_key"]
                save_ca(ca)
                conn.send(json.dumps({"status": "registered"}).encode())

        elif request["action"] == "get_key":
            user = request["username"]
            if user not in ca:
                conn.send(json.dumps({"error": "User not found"}).encode())
            else:
                conn.send(json.dumps({"public_key": ca[user]}).encode())

    except Exception as e:
        print(f"[ERROR] {addr}: {e}")
    finally:
        conn.close()

#Start server
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[CA SERVER RUNNING] {HOST}:{PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
