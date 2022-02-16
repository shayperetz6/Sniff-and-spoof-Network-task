#!/usr/bin/python

from scapy.all import *

def print_pkt(pkt):
    pkt.show()


pkt = sniff(iface=['enter the net line', 'enp0s3', 'lo'], filter='icmp', prn=print_pkt)