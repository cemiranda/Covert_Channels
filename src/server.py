import socket
import ssl
import threading

def handle_client(client_sock):
    try:
        data = client_sock.recv(65535)

        # If potential packet used for covert data, validate it's legit json (TBD)
        # and the data wasn't modified in transit
        if b"POST" in data and b"application/json" in data:
            print("Server: Received POST request")

        # Always respond with everything is ok
        response = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"status\":\"success\"}"
        client_sock.send(response)
        print("Server: Sent 200 OK response")
        client_sock.close()
    except Exception as e:
        print(f"Legit Server: Error: {e}")

def start_server():
    # Create context with keys
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="/certs/server.crt", keyfile="/certs/server.key")

    # Bind a socket for listening for requests
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock = context.wrap_socket(sock, server_side=True)
    sock.bind(("0.0.0.0", 443))
    sock.listen(5)

    print("Server: Listening on port 443...")
    while True:
        client_sock, addr = sock.accept()
        threading.Thread(target=handle_client, args=(client_sock,), daemon=True).start()

if __name__ == "__main__":
    start_server()