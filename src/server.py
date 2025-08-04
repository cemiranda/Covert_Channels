#!/usr/bin/env python3
import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler

LISTEN_ADDR = ("0.0.0.0", 443)

class SimpleHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)
        print("Server: received ", body.decode(errors="ignore"))

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"success"}')
        self.close_connection = True

    def log_message(self, fmt, *args):
        # suppress default logging
        return

if __name__ == "__main__":
    
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile="./certs/server.crt", keyfile="./certs/server.key")
    ctx.load_verify_locations(cafile="./certs/ca.crt")
    ctx.verify_mode = ssl.CERT_REQUIRED

    httpd = HTTPServer(LISTEN_ADDR, SimpleHandler)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"Server: HTTPS listening on {LISTEN_ADDR[0]}:{LISTEN_ADDR[1]}")
    httpd.serve_forever()
