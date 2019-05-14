#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
    # --help features
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target", help="Target IP (10.0.0.1) or IP Range (10.0.0.1/24).")
    (options, arguments) = parser.parse_args()
    return options

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

    # Dict usage - for reusable reasons
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

# Stand alone print func - reusable
def print_result(results_list):
    print("IP\t\t\tMAC Address\n")+("-" * 60)
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)
