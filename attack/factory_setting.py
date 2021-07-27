import os
import sys
import threading
import time



 
def reset_setting():
    os.system('service NetworkManager start')
    os.system('service apache2 stop')
    os.system('service hostapd stop')
    os.system('service dnsmasq stop')
    os.system('service rpcbind stop')
    os.system('killall dnsmasq')
    os.system('killall hostapd')
    os.system('systemctl enable systemd-resolved.service')
    os.system('systemctl start systemd-resolved')


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
    reset_setting()
    remove_conf_files()
