from scapy.all import *
from scapy.layers.inet import ICMP, IP


def send_packet(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # if it is a echo request

        src = pkt[IP].src
        dst = pkt[IP].dst
        seq = pkt[ICMP].seq
        id = pkt[ICMP].id

        load = pkt[Raw].load
        reply = IP(src=dst, dst=src) / ICMP(type=0, id=id, seq=seq) / load
        print("sniffing echo request from", pkt[IP].src )
        print(" sending echo reply to ", pkt[IP].dst)
        send(reply, verbose=False)


pkt = sniff(iface="fill the net name", filter="icmp", prn=send_packet)
