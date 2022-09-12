
# Building a Network Scanner #

import scapy.all as scapy
import argparse

def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest= 'target', help= 'Target IP Address/Addresses')
    options = parser.parse_args()


    # Check for errors i.e if the user does not specify the target IP address
    # Quit the program if the argument is missing
    # While quitting also display an error message

    if not options.target:
        #Code to handle if interface is not specified
        parser.error("[-] Please specify an IP Address or Adresses, use --help for more info.")
    return options



# The code from above can be used with this command root@kali:~# python3 network_scanner.py -t IP_Address/IP_Addresses 

def scan(ip):
    arq_req_frame = scapy.ARP(pdst = ip)

    broadcast_ether_frame = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")

    broadcast_ether_arp_req_frame = broadcast_ether_frame / arp_req_frame 

    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout = 1, verbose = False) [0]
    result = []
    for i in range(0, len(answered_list)):
        client_dict = {"ip" : answered_list[i][1].psrc, "mac" : answered_list[i][1].hwsrc}
        result.append(client_dict)

    return result

options = get_args()
scanned_output = scan(options.target)