from scapy.all import *
from scapy.layers.inet import ICMP, IP

for i in range(1, 50):
    a = IP()
    a.dst = "1.2.3.4"
    a.ttl = i
    b = ICMP()
    send(a/b)
