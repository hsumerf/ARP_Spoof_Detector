#!/usr/bin/env python
import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    #this mac is for broadcast
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
# this line will return 2 lists, answered and unanswered.Timeout will specify time to request
    while True:
        try:
            answered_list = scapy.srp(arp_request_broadcast,timeout=2,verbose=False)[0]#verbose=False for no output on console
            mac = answered_list[0][1].hwsrc
            return mac
        except:
            pass
def sniff(interface):
    scapy.sniff(iface=interface,store=False,prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        real_mac = get_mac(packet[scapy.ARP].psrc)
        response_mac = packet[scapy.ARP].hwsrc
        if real_mac != response_mac:
            print("under attack By" + real_mac + "pretending to be "+response_mac)

sniff("eth0")
