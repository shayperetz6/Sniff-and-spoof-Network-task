from scapy.all import *


def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface=['enter the net line', 'enp0s3', 'lo'], filter="dst port 23 and src host (fill the ip)", prn=print_pkt)
