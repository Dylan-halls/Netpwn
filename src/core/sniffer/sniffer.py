#! /usr/bin/env python

#system imports
import socket
import sys
import os

#impacket imports
from impacket.ImpactDecoder import EthDecoder

#netpwn imports
os.sys.path.append(os.path.dirname(os.path.abspath('.'))) #fix import path
from logger.logger import Logger

#protocol numbers
IP_PROTO_TCP  = 6
IP_PROTO_UDP  = 17
IP_PROTO_ICMP = 1
ETHERTYPE_IP  = 0x0800
ETHERTYPE_ARP = 0x0806

class Sniffer(object):
    """Raw socket packet sniffer."""
    def __init__(self):
        """
        control variables
        """
        super(Sniffer, self).__init__()
        self.sock = None
        self.log  = Logger("/dev/stdout")

    def init(self, iface):
        """
        opens the raw socket and bind to interface, also checks for root
        """
        self.iface = iface
        if os.getuid() == 0:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)
            self.sock.bind((iface, 0x0003))
        else:
            self.log.critical("Needs to be root")
            exit(-1)

    def _decode_tcp(self, packet):
        """
        decode and assign tcp packet
        """
        self.packet['TCP_SPORT']    = packet.get_th_sport()
        self.packet['TCP_DPORT']    = packet.get_th_dport()
        self.packet['TCP_SYN']      = packet.get_SYN()
        self.packet['TCP_ACK']      = packet.get_ACK()
        self.packet['TCP_CWR']      = packet.get_CWR()
        self.packet['TCP_RST']      = packet.get_RST()
        self.packet['TCP_ECE']      = packet.get_ECE()
        self.packet['TCP_FIN']      = packet.get_FIN()
        self.packet['TCP_PSH']      = packet.get_PSH()
        self.packet['TCP_URG']      = packet.get_URG()
        self.packet['TCP_FLAGS']    = packet.get_th_flags()
        self.packet['TCP_OFFSET']   = packet.get_th_off()
        self.packet['TCP_RESERVED'] = packet.get_th_reserved()
        self.packet['TCP_SEQ_NUM']  = packet.get_th_seq()
        self.packet['TCP_ACK_NUM']  = packet.get_th_ack()
        self.packet['TCP_SUM']      = packet.get_th_sum()
        self.packet['TCP_URP']      = packet.get_th_urp()
        self.packet['TCP_WIN']      = packet.get_th_win()
        self.packet['TCP_PAYLOAD']  = packet.get_data_as_string()

    def _decode_udp(self, packet):
        self.packet['UDP_SPORT']   = packet.get_uh_sport()
        self.packet['UDP_DPORT']   = packet.get_uh_dport()
        self.packet['UDP_SUM']     = packet.get_uh_sum()
        self.packet['UDP_LEN']     = packet.get_uh_ulen()
        self.packet['UDP_PAYLOAD'] = packet.get_data_as_string()

    def _decode_icmp(self, packet):
        """
        decode and assign icmp packet
        """
        self.packet['ICMP_GWADDR']   = packet.get_icmp_gwaddr()
        self.packet['ICMP_PAYLOAD']  = packet.get_data_as_string()
        self.packet['ICMP_CHSUM']    = packet.get_icmp_cksum()
        self.packet['ICMP_CODE']     = packet.get_icmp_code()
        self.packet['ICMP_ID']       = packet.get_icmp_id()
        self.packet['ICMP_LIFE']     = packet.get_icmp_lifetime()
        self.packet['ICMP_MASK']     = packet.get_icmp_mask()
        self.packet['ICMP_NXT_MTU']  = packet.get_icmp_nextmtu()
        self.packet['ICMP_NUM_ADDR'] = packet.get_icmp_num_addrs()
        self.packet['ICMP_OTIME']    = packet.get_icmp_otime()
        self.packet['ICMP_RTIME']    = packet.get_icmp_rtime()
        self.packet['ICMP_SEQ']      = packet.get_icmp_seq()
        self.packet['ICMP_TTIME']    = packet.get_icmp_ttime()
        self.packet['ICMP_TYPE']     = packet.get_icmp_type()
        self.packet['ICMP_VOID']     = packet.get_icmp_void()
        self.packet['ICMP_WPA']      = packet.get_icmp_wpa()

    def _decode_ip(self, packet):
        """
        decodes the ip packet and creates the decoded packet
        """

        #add respective values to dictionary
        self.packet['IP_VERSION'] = packet.get_ip_v()
        self.packet['IP_IHL']     = packet.get_ip_hl()
        self.packet['IP_TOS']     = packet.get_ip_tos()
        self.packet['IP_LEN']     = packet.get_ip_len()
        self.packet['IP_ID']      = packet.get_ip_id()
        self.packet['IP_OFFSET']  = packet.get_ip_off()
        self.packet['IP_TTL']     = packet.get_ip_ttl()
        self.packet['IP_PROTO']   = packet.get_ip_p()
        self.packet['IP_CHSUM']   = packet.get_ip_sum()
        self.packet['IP_SRC']     = packet.get_ip_src()
        self.packet['IP_DST']     = packet.get_ip_dst()

        #pass to packets child to their decoder function
        if packet.get_ip_p() == IP_PROTO_TCP:
            self._decode_tcp(packet.child())
        elif packet.get_ip_p() == IP_PROTO_UDP:
            self._decode_udp(packet.child())
        elif packet.get_ip_p() == IP_PROTO_ICMP:
            self._decode_icmp(packet.child())

    def _decode_arp(self, packet):
        """
        decodes the arp packet
        """
        #print dir(packet)
        self.packet['ARP_HLN']     = packet.get_ar_hln()
        self.packet['ARP_HRD']     = packet.get_ar_hrd()
        self.packet['ARP_OPT']     = packet.get_ar_op()
        self.packet['ARP_PLN']     = packet.get_ar_pln()
        self.packet['ARP_PRO']     = packet.get_ar_pro()
        self.packet['ARP_SHA']     = ':'.join([hex(i)[2:] for i in packet.get_ar_sha()])
        self.packet['ARP_THA']     = ':'.join([hex(i)[2:] for i in packet.get_ar_tha()])
        self.packet['ARP_TPA']     = '.'.join([str(i) for i in packet.get_ar_tpa()])
        self.packet['ARP_SPA']     = '.'.join([str(i) for i in packet.get_ar_spa()])
        self.packet['ARP_PAYLOAD'] = packet.get_data_as_string()

    def _packet_handler(self, packet):
        """
        decode ethernet packet and pass packets child to decoding function
        """
        decoder = EthDecoder()
        dpkt = decoder.decode(packet)
        if dpkt.get_ether_type() == ETHERTYPE_IP:
            self._decode_ip(dpkt.child())
        if dpkt.get_ether_type() == ETHERTYPE_ARP:
            self._decode_arp(dpkt.child())

        return self.packet

    def sniff(self):
        """
        sniffs from self.sock
        """
        while True:
            self.packet = {}
            pkt = self.sock.recvfrom(65565)
            if pkt[1][0] != self.iface:
                continue
            dpkt = self._packet_handler(pkt[0])
            if len(dpkt) != 0:
                return dpkt

    def shutdown(self):
        """
        cleanly shuts down the socket
        """
        self.sock.close()
        self.sock = None

if __name__ == '__main__':
    sniffer = Sniffer()
    sniffer.init("wlp3s0")
    while True:
        print sniffer.sniff()
