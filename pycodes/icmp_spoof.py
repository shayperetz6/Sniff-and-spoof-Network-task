from scapy.all import *
from scapy.layers.inet import ICMP, IP

a = IP()
a.src = "8.8.8.8"
a.dst = "10.9.0.1"
b = ICMP()
p = a / b
send(p)
ls(a)
