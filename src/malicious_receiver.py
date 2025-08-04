from scapy.all import IP, TCP, Ether, get_if_hwaddr, Raw, sendp, sniff
from scapy.config import conf
conf.use_pcap = True

from config import *

from utils import print_pkt


# Configuration
LEFT_IF = "enp0s3"
RIGHT_IF = "enp0s8"

def intercept_packet(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == SERVER_IP \
            and pkt[TCP].dport == SERVER_PORT and pkt[Ether].src != get_if_hwaddr(RIGHT_IF):
        
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            if MARKER in data:

                orig, covert = data.split(MARKER, 1)
                print(f"Covert data: {covert}")

                new_pkt = pkt.copy()

                # Remove everything after the marker
                new_pkt[TCP].remove_payload()
                new_pkt = new_pkt / Raw(orig)

                # Update MAC addresses
                new_pkt[Ether].src = get_if_hwaddr(RIGHT_IF)
                new_pkt[Ether].dst = SERVER_MAC

                # Remove checksums that have become invalidated by our tampering
                del new_pkt[IP].len
                del new_pkt[IP].chksum
                del new_pkt[TCP].chksum 

                sendp(new_pkt, iface=RIGHT_IF, verbose=False)

    elif pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == CLIENT_IP and pkt[Ether].src != get_if_hwaddr(LEFT_IF):

        # No longer used as we don't mess with return messages. Cover channel is one way

        pkt.src = get_if_hwaddr(LEFT_IF)
        pkt.dst = SENDER_RIGHT_MAC

        del pkt[IP].chksum
        del pkt[TCP].chksum 

        sendp(pkt, iface=LEFT_IF, verbose=False)

if __name__ == "__main__":
    print("Malicious Receiver: Starting packet sniffer...")

    client_side_mac  = get_if_hwaddr(LEFT_IF)
    server_side_mac = get_if_hwaddr(RIGHT_IF)
    bpf_filter = f"not ether src {client_side_mac} and not ether src {server_side_mac}"

    try:
        sniff(iface=[LEFT_IF], filter=bpf_filter, prn=intercept_packet, store=0)
    except Exception as e:
        print(f"Malicious Sender: Error: {e}")
