from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import os
import time

ap_list = []
ESSID = 0
BSSID = 1
CHANNEL = 2
essids_set = set()

global search_timeout
global ap_mac
global ap_name
global ap_channel
global count


def monitor_mode():
    global interface
    print("*** Step 1:  Choosing an interface to put in 'monitor mode'. *** \n")
    empty = input("Press Enter to continue.........\n")
    os.system('ifconfig')
    interface = input("Please enter the interface name you want to put in 'monitor mode': ")

    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode monitor')
    os.system('ifconfig ' + interface + ' up')


def managed_mode():
    print("\n*** Step 4: Put the interface back in 'managed mode'. *** \n")
    empty = input("Press Enter in order to put " + interface + " in 'managed mode' .........\n")

    os.system('ifconfig ' + interface + ' down')
    os.system('iwconfig ' + interface + ' mode managed')
    os.system('ifconfig ' + interface + ' up')
    print("[**] - The interface: " + interface + ", is now in Managed Mode. \nYou can check it here : \n")
    os.system('iwconfig')


def ap_scan_rap():
    print("*** Step 2: Scanning the network for AP to attack. *** \n")
    empty = input("Press Enter to continue.........")
    ap_scan()


def ap_scan():
    search_timeout = int(input("Please enter the scanning time frame in seconds: "))
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()
    print("\n Scanning for networks...\n")

    sniff(iface=interface, prn=ap_scan_pkt, timeout=search_timeout)
    num_of_ap = len(ap_list)
    if num_of_ap > 0:
        print("\n*************** APs Table ***************\n")
        for x in range(num_of_ap):
            print("[" + str(x) + "] - BSSID: " + ap_list[x][BSSID] + " \t Channel:" + str(
                ap_list[x][CHANNEL]) + " \t AP name: " + ap_list[x][ESSID])
        print("\n************* FINISH SCANNING *************\n")

        ap_index = int(input("Please enter the number of the AP you want to defence: "))
        print("You choose the AP: [" + str(ap_index) + "] - BSSID: " + ap_list[ap_index][BSSID] + " Channel:" + str(
            ap_list[ap_index][CHANNEL]) + " AP name: " + ap_list[ap_index][ESSID])

        ap_mac = ap_list[ap_index][BSSID]
        ap_name = ap_list[ap_index][ESSID]
        ap_channel = ap_list[ap_index][CHANNEL]
    else:
        rescan = input("No networks were found. Do you want to rescan? [Y/n] ")
        if rescan == "n":
            print("  Sorry :(  ")
            managed_mode()
            sys.exit(0)
        else:
            ap_scan()


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


def deathentication_check():
    print("*** Step 3: Sniffing the packets and checking for deauthentication attack. *** \n")
    print(
        "In case that will be sniffed 30 deauthentication packets, you will alerted that there is attempt to do deathentication attack to the AP you choose. \n")
    empty = input("Press Enter to continue.........\n")
    print("Sniffing packets for 60 second ...")

    sniff(iface=interface, prn=packet_handler, stop_filter=stopfilter)





def packet_handler(pkt):
    global count
    global start_time

    if pkt.type == 0 and pkt.subtype == 0xC:
        try:

            if ap_mac in str(pkt.addr2):
                count = count + 1
                print("Deauthentication packet has been sniffed. Packet number: " + str(count))
        except:
            print("An exception occurred")
    # If 60 sec had passed and deauthentication attack didn't occur, than we reset count to 0 and start counting again
    if time.time() - start_time > 60:
        count = 0
        print("Meanwhile, everything is OK :) ")
        start_time = time.time()


def stopfilter(x):
    if count == 30:
        print("WARNNING!! There is attemp to do deathentication attack on your netwotk. \n")
        return True
    else:
        return False


if __name__ == "__main__":

    if os.geteuid():
        sys.exit('[**] Please run as root')

    print("********************************************************************** \n")
    print("************ Part 3: defence from deauthentication attack ************ \n")
    print("********************************************************************** \n")

    monitor_mode()

    ap_scan_rap()

    start_time = time.time()
    deathentication_check()

    managed_mode()
