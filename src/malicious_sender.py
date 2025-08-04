from scapy.all import IP, TCP, Ether, get_if_hwaddr, Raw, sendp, sniff
from scapy.config import conf
conf.use_pcap = True

import random

from config import *
from utils import print_pkt

LEFT_IF = "enp0s3"
RIGHT_IF = "enp0s8"

chance_of_covert_data = .1

def inject_packet(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == SERVER_IP  \
            and pkt[TCP].dport == SERVER_PORT and pkt[Ether].src == CLIENT_MAC: 
        
        # Only inject malicious data .1% of the time to avoid being noisy
        if random.random() < chance_of_covert_data:

            print("Injecting covert data into packet")

            # Append our covert data to the new payload
            payload = bytes(pkt[TCP].payload)
            covert_message = b"hello_from_the_covert_channel"
            new_payload = payload + MARKER + covert_message
            pkt[TCP].payload = Raw(new_payload)

            # Update MAC addresses
            pkt[Ether].src = get_if_hwaddr(RIGHT_IF)
            pkt[Ether].dst = RECEIVER_LEFT_MAC

            # Update checksums and length on the IP packet
            del pkt[IP].len
            del pkt[TCP].chksum
            del pkt[IP].chksum

            sendp(pkt, iface=RIGHT_IF, verbose=False)

    elif pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == CLIENT_IP and pkt[Ether].src != get_if_hwaddr(LEFT_IF):

        # No longer used as we don't mess with return messages. Cover channel is one way

        pkt.src = get_if_hwaddr(LEFT_IF)
        pkt.dst = CLIENT_MAC

        del pkt[IP].chksum, pkt[TCP].chksum 
        sendp(pkt, iface=LEFT_IF, verbose=False)

if __name__ == "__main__":
    print("Malicious Sender: Starting packet sniffer...")
    client_side_mac  = get_if_hwaddr(LEFT_IF)
    server_side_mac = get_if_hwaddr(RIGHT_IF)
    bpf_filter = f"not ether src {client_side_mac} and not ether src {server_side_mac}"

    try:
        sniff(iface=[LEFT_IF], filter=bpf_filter, prn=inject_packet, store=0)
    except Exception as e:
        print(f"Malicious Sender: Error: {e}")
