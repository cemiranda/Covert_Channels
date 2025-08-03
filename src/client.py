import time
import requests

def send_https_request():
    
    # URL of server hosting a fake github instance for demonstration purposes 
    url = "https://10.0.4.10:443/api"

    # Fake data as if making a push to github
    headers = {
                "Host": "github.com",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0"
              }
    data =  {
                "action": "push",
                "repo": "test-repo"
            }

    try:
        # Send message to the fake server
        response = requests.post(url, headers=headers, json=data, cert=("./certs/client.crt", "./certs/client.key"), verify=False)
        print(f"Client: Sent POST request, response: {response.status_code}")
        print(f"Client: Response body is {response.text}")
    except Exception as e:
        print(f"Client: Error sending request: {e}")

if __name__ == "__main__":
    # Send 10 messages sleeping 10 seconds between each
    print("Client: Starting up..")
    for i in range(0, 9):
        print(f"Client: Sending the {i}th packet")
        send_https_request()
        time.sleep(10)
