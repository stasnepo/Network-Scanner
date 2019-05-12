#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    # Ask who has IP x (scan)
    arp_request = scapy.ARP(pdst=ip)
    # MAC destination
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combination of requests
    arp_request_broadcast = broadcast/arp_request
    # Need to capture 2 responses from that request (answered, unanswered will hold the value)
    # [0] represent only Answered List
    # If no response, timeout and move on
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print("IP\t\t\tMAC Address\n")+("-" * 60)
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


scan("10.0.2.1/24")
