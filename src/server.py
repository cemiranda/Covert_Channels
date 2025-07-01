from http.server import SimpleHTTPRequestHandler, HTTPServer


def serve(host, port):
    server = HTTPServer((host, port), SimpleHTTPRequestHandler)
    print(f"Serving HTTP on {host}:{port}")
    server.serve_forever()

if __name__ == "__main__":

    serve("0.0.0.0", 8000)

