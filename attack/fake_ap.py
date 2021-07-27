import os
import sys

global essid
global interface

def reset_setting():
    os.system('service NetworkManager start')
    os.system('service apache2 stop')
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('service rpcbind stop')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    os.system('systemctl enable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl start systemd-resolved >/dev/null 2>&1')


def fake_ap_on():
    os.system('systemctl disable systemd-resolved.service >/dev/null 2>&1')
    os.system('systemctl stop systemd-resolved>/dev/null 2>&1')
    os.system('service NetworkManager stop')
    os.system(' pkill -9 hostapd')
    os.system(' pkill -9 dnsmasq')
    os.system(' pkill -9 wpa_supplicant')
    os.system(' pkill -9 avahi-daemon')
    os.system(' pkill -9 dhclient')
    os.system('killall dnsmasq >/dev/null 2>&1')
    os.system('killall hostapd >/dev/null 2>&1')
    set_ap_ip="ifconfig " + interface + " 10.0.0.1 netmask 255.255.255.0"
    os.system(set_ap_ip)
    os.system('route add default gw 10.0.0.1')
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    os.system('iptables --flush')
    os.system('iptables --table nat --flush')
    os.system('iptables --delete-chain')
    os.system('iptables --table nat --delete-chain')
    os.system('iptables -P FORWARD ACCEPT')


def run_fake_ap():
    os.system('dnsmasq -C dnsmasq.conf')
    os.system('service apache2 start')
    os.system('gnome-terminal -- sh -c "node html/index2.js"')
    os.system('route add default gw 10.0.0.1')
    os.system('hostapd hostapd.conf -B')
    os.system('route add default gw 10.0.0.1')


def create_conf_files():
    line="python3 create_conf_files.py " + interface + " " + essid
    os.system(line)


def remove_conf_files():
    try:
        os.remove("dnsmasq.conf")
    except OSError:
        pass
    try:
        os.remove("hostapd.conf")
    except OSError:
        pass


if __name__ == "__main__":

    print("Set up & upload fake AP. \n")
    print( "Choosing an interface that will be used for the fake AP. \n")
    empty = input ("Press Enter to continue")
    os.system('ifconfig')
    interface = input("Please enter the interface name you want to use: ")

    reset_setting()


    essid = sys.argv[1]

    print("Activation of the fake AP. \n")
    empty = input ("Press Enter to continue")
    fake_ap_on()
    create_conf_files()
    run_fake_ap()

    print(" Deactivation of the fake AP\n")
    empty = input ("\nPress Enter to Close Fake Accses Point AND Power OFF the fake AP.........\n")
    remove_conf_files()
    reset_setting()

    print("Everything returned back to default setting. \nHopes to see you soon :) ***\n")



