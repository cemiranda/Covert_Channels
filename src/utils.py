from scapy.all import *

def print_pkt(pkt):
    if not (pkt.haslayer(Ether) and pkt.haslayer(IP)):
        return

    eth = pkt[Ether]
    ip_layer = pkt[IP]

    if pkt.haslayer(TCP):
        l4 = pkt[TCP]
    else:
        return

    eth_src = eth.src
    eth_dst = eth.dst
    ip_src  = ip_layer.src
    ip_dst  = ip_layer.dst
    sport   = l4.sport
    dport   = l4.dport

    print(
        f"Ether: {eth_src} to {eth_dst} | "
        f"IP: {ip_src}:{sport} to {ip_dst}:{dport} ",
        flush=True
    )