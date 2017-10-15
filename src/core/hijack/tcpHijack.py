#! /usr/bin/env python

import socket
import libnet
from libnet.constants import *

inj = libnet.context(LINK, "wlp3s0")
srcip = socket.inet_ntoa(inj.get_ipaddr4())

tcptag = inj.build_tcp(dp=1443, sp=1, control=TH_SYN, payload="Hi")
iptag = inj.build_ipv4(prot=IPPROTO_TCP, dst=socket.inet_aton("192.168.1.175"))
ethtag = inj.build_ethernet()

for i in range(0, 100):
    inj.write()
