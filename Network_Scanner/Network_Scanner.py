#!/usr/bin/env python
import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP address or Network to Scan")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target IP or network, use --help for more info.")
    return options

def scan(ip):
    arp_request = scapy.ARP(pdst=ip) # make arp
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # make broadcast ethernet frame
    arp_request_broadcast = broadcast/arp_request # arp encapsulated by ethernet frame
    # arp_request_broadcast.show()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) # send arp and get arp response

    client_list = []
    for answer in answered_list:
        # print(answer[1].show()) # only capture response part
        client_dict = {"IP": answer[1].psrc, "MAC": answer[1].hwsrc}
        client_list.append(client_dict)

    return client_list

def print_result(client_list):
    print("IP\t\t\tMAC Address\n-----------------------------------------------------")
    for client in client_list:
        print(f'{client["IP"]}\t\t{client["MAC"]}')

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

