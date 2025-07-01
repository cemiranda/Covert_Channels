import time
import urllib.request

SERVER_URL = "http://172.28.0.2:8000"

def run_client(server):
    while True:
        try:
            with urllib.request.urlopen(server) as response:
                content = response.read().decode()
                print("Server response:\n", content)
        except Exception as e:
            print("Error:", e)

        time.sleep(5)

if __name__ == "__main__":

    server = SERVER_URL
    run_client(server)
