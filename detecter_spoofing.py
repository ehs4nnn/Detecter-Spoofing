#!/usr/bin/env python
import scapy.all as scapy

figlet_tool_style = """
	 ____       _            _               ____                     __ _             
	|  _ \  ___| |_ ___  ___| |_ ___  _ __  / ___| _ __   ___   ___  / _(_)_ __   __ _ 
	| | | |/ _ \ __/ _ \/ __| __/ _ \| '__| \___ \| '_ \ / _ \ / _ \| |_| | '_ \ / _` |
	| |_| |  __/ ||  __/ (__| || (_) | |     ___) | |_) | (_) | (_) |  _| | | | | (_| |
	|____/ \___|\__\___|\___|\__\___/|_|    |____/| .__/ \___/ \___/|_| |_|_| |_|\__, |
						      |_|                            |___/ 

	       <-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+->
				    By: EhSaN FaRaMaRz
			    GiTHuB: https://github.com/ehs4nnn/
			     yOuTubE: https://bit.ly/3aiMyjV
				EmAiL: ehsan@rajekar.com
	       <-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+->
"""

print(figlet_tool_style)

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = broadcast/arp_request 
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	return answered_list[0][1].hwsrc
	
	
def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)



def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
		try:
			real_mac = get_mac(packet[scapy.ARP].psrc)
			response_mac = packet[scapy.ARP].hwsrc
			
			if real_mac != response_mac:
				print("[+] You're Under Attack!!!")
			else:
				print("Everything is Normal :)")
					
		except IndexError:
			pass
			
		


sniff("wlan0")
