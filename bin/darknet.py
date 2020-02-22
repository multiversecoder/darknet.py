#!/usr/bin/python3

__author__ = "Adriano Romanazzo"
__copyright__ = "Copyright 2019, Adriano Romanazzo (https://github.com/multiversecoder)"
__license__ = "The 3-Clause BSD License"
__maintainer__ = "https://github.com/multiversecoder"
__status__ = "Stable"

import os
import sys
import time
import shlex
import shutil
import signal
import random
import argparse
import subprocess
import inspect
from urllib.request import urlopen

USAGE = """
    normal mode
        $ darknet.py --start --torid 104
    stealth mode
        $ darknet.py --stealth --torid 104 --ifaces [enp1s0]
    stopping
        $ darknet.py --stop

NOTES:
    <interface(s)> should be added as python list [wlo1, ...]

DISCLAIMER:
    The author of this software assumes no responsibility for the use of this software to perform actions that do not comply with the law or damage property or individuals.
    Using this software you take full responsibility for your actions.
"""

parser = argparse.ArgumentParser(usage=USAGE)
parser.add_argument("--start", help="Starts the transparent proxy", action="store_true")
parser.add_argument("--stealth", help="Changes MAC Address and Starts the transparent proxy", action="store_true")
parser.add_argument("--stop", help="Stop the execution and reset configurations", action="store_true")
parser.add_argument("--torrc", help="The location of torrc config file", type=str)
parser.add_argument("--torid", help="The TOR Process ID", type=int)
parser.add_argument("--port", help="The tor service port", type=int)
parser.add_argument("--ifaces", help="Add interfaces to change mac address", type=str)

class PermissionDenied(Exception):
    pass

class TORNotInstalled(Exception):
    pass

class MissingTORID(Exception):
    pass

class MissingInterfacesForStealthMode(Exception):
    pass

class UnsupportedOS(Exception):
    pass

class Darknet:

    def __init__(self):
        self.__check_if_linux()
        self.logo = """
            ___           _               _
           /   \__ _ _ __| | ___ __   ___| |_
          / /\ / _` | '__| |/ / '_ \ / _ \ __|
         / /_// (_| | |  |   <| | | |  __/ |_
        /___,' \__,_|_|  |_|\_\_| |_|\___|\__| .py

        v1.0 - https://github.com/multiversecode/darknet.py
        Using this software you take full responsibility for your actions
        run darknet.py -h to see help, full disclaimer or usage
        """
        signal.signal(signal.SIGINT, self.__handle_sigint)
        self.__check_if_tor_installed()

    def __ntpsync(self) -> None:
        #subprocess.call(shlex.split("sudo ntpdate -s time.nist.gov"))
        pass

    def __check_if_linux(self) -> None:
        if "linux" not in sys.platform:
            raise UnsupportedOS("You need a Linux distro to run this program")
    
    def __sel(self, en: int) -> bool:
        if bool(shutil.which("setenforce")) is not False:
            subprocess.call(shlex.split("setenforce {}".format(en)))
            return True
        return False

    def __check_if_tor_installed(self) -> None:
        if bool(shutil.which("tor")) is False:
            raise TORNotInstalled("TOR not installed... Please install TOR to get it on your system")

    def __handle_sigint(self, signum, frame):
        print('\nKeyBoard Interrupt Detected\nShutting Down Darknet\n')
        print("{} [info] shutting down darknet.py\n\n".format(self._timer))
        self.stop()
        sys.exit(1)

    @property
    def __has_internet_connection(self) -> bool:
        while True:
            try:
                urlopen('https://check.torproject.org/', timeout=1)
                return True
            except:
                continue
            break

    @property
    def __check_ip_addr(self)-> str:
        if self.__has_internet_connection and self.has_tor:
            return "TOR is enabled\n {}".format(
                    subprocess.getoutput(
                        "curl -s https://check.torproject.org/ | cat | grep -m 1 IP | xargs | sed 's/<[^>]*>//g'")
                    )
        elif self.__has_internet_connection and not self.has_tor:
            return "TOR is disabled\nYour IP address appears to be: {}".format(subprocess.getoutput("curl -s ipinfo.io/ip"))

    @property
    def _timer(self):
        return "[{}]".format(time.strftime('%H:%M:%S', time.localtime()))

    def __set_iptables_rules(self, torid: int, tport: int = None,
            nontor: str = "0.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12  203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24") -> str:
        return """
        /usr/sbin/iptables -F
        /usr/sbin/iptables -t nat -F
        /usr/sbin/iptables -t nat -A OUTPUT -m owner --uid-owner {torid} -j RETURN
        /usr/sbin/iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
        for NET in {nontor}; do
            /usr/sbin/iptables -t nat -A OUTPUT -d $NET -j RETURN
        done
        /usr/sbin/iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports {tport}
        /usr/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        for NET in {nontor}; do
            /usr/sbin/iptables -A OUTPUT -d $NET -j ACCEPT
        done
        /usr/sbin/iptables -A OUTPUT -m owner --uid-owner {torid} -j ACCEPT
        /usr/sbin/iptables -A OUTPUT -j REJECT""".format(
                torid=torid,
                tport=tport if tport is not None else 9040,
                nontor=nontor
            )


    def __unset_iptables_rules(self) -> str: 
        return """
            /usr/sbin/iptables -P INPUT ACCEPT
            /usr/sbin/iptables -P FORWARD ACCEPT
            /usr/sbin/iptables -P OUTPUT ACCEPT
            /usr/sbin/iptables -t nat -F
            /usr/sbin/iptables -t mangle -F
            /usr/sbin/iptables -F
            /usr/sbin/iptables -X
        """

    def __torrc_file(self, tport: int) -> str:
        return inspect.cleandoc("""
                # THIS FILE IS GENERATED BY
                #       DARKNET.PY
                AvoidDiskWrites 1
                GeoIPFile /usr/local/share/tor/geoip
                GeoIPv6File /usr/local/share/tor/geoip6
                VirtualAddrNetworkIPv4 10.0.0.0/10
                AutomapHostsOnResolve 1
                ExcludeNodes {{AU}}, {{CA}}, {{US}}, {{NZ}}, {{GB}}, {{DK}}, {{FR}}, {{NL}}, {{NO}}, {{BE}}, {{DE}}, {{IT}}, {{ES}}, {{SE}}
                NodeFamily {{AU}}, {{CA}}, {{US}}, {{NZ}}, {{GB}}, {{DK}}, {{FR}}, {{NL}}, {{NO}}, {{BE}}, {{DE}}, {{IT}}, {{ES}}, {{SE}}
                StrictNodes 1
                TransPort {tport} IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
                DNSPort 5353
        """.format(
                tport=tport if tport is not None else 9040
            )
        )

    def __check_if_root(self) -> None:
        if os.getuid() != 0:
            raise PermissionDenied("You must be root to run this program")

    @property
    def __random_mac_address(self) -> str:
        return "02:00:00:%2x:%2x:%2x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255))

    def __change_mac_addr(self, interfaces: list) -> None:
        print("{} Changing MAC Addresses...".format(self._timer))
        for interface in interfaces:
            print("{} Changing: {}".format(self._timer, interface))
            subprocess.call(shlex.split("/bin/ip link set {} down".format(interface)))
            time.sleep(5)
            macaddr = self.__random_mac_address
            subprocess.call(shlex.split("/bin/ip link set {} address {}".format(interface, macaddr)))
            time.sleep(5)
            subprocess.call(shlex.split("/bin/ip link set {} up".format(interface)))
            print("{} MAC Addresses changed for interface: {} => {} ".format(self._timer, interface, macaddr))
            print("{} Reloading Network Manager".format(self._timer))
            subprocess.call(shlex.split("systemctl reload NetworkManager"))
            time.sleep(10)
        print("[done]")

    def __set_torrc_config(self, torrc_content: str) -> None:
        with open("/etc/tor/torrc", "w") as torrc:
            print("{} Configuring torrc file.. ".format(self._timer, end=""))
            torrc.write(torrc_content)
            print("[done]")

    def __open_user_torrc_config(self, torrc_location: str) -> str:
        with open(torrc_location, "r") as torrc:
            torrc = torrc.read()
        return torrc

    def __backup_old_torrc(self) -> str:
        if not os.path.exists("/etc/tor/torrc.orig"):
            with open("/etc/tor/torrc.orig", "w+") as torrc_orig:
                torrc_orig.write(self.__open_user_torrc_config("/etc/tor/torrc"))

    def __torrc_config(self, torrc: str, tport: int = None) -> None:
        torrc = self.__open_user_torrc_config(torrc) if torrc is not None else self.__torrc_file(tport)
        with open("/etc/tor/torrc") as torrc_old:
            torrc_old = torrc_old.read()
        if torrc == torrc_old:
            print("{} torrc file already configured".format(self._timer))
        else:
            print("{} Backup torrc file => /etc/tor/torrc.orig".format(self._timer))
            self.__backup_old_torrc()
            self.__set_torrc_config(torrc)

    @property
    def __resolv_config(self) -> None:
        with open("/etc/resolv.conf") as resolv_conf:
            resolv_conf = resolv_conf.read()
        if resolv_conf == "nameserver 127.0.0.1":
            print("{} DNS resolv.conf file already configured".format(self._timer))
        else:
            self.__set_resolv_config("nameserver 127.0.0.1")


    def __set_resolv_config(self, resolv_content: str) -> None:
        with open("/etc/resolv.conf", "w") as resolvconf:
            print("{} Configuring DNS resolv.conf file.. ".format(
                self._timer), end="")
            resolvconf.write(resolv_content)
            print("[done]")

    @property
    def has_tor(self) -> bool:
        status_message = subprocess.getoutput(
        "curl -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs")
        if "Congratulations" in status_message:
            return True
        elif "Sorry. You are not using TOR" in status_message:
            return False
        else:
            return False

    def restart_tor(self) -> None:
        subprocess.call(shlex.split("systemctl restart tor.service"))

    def start(self, torid: int, torrc: str = None, port: int = None) -> None:
        self.__torrc_config(torrc, port)
        self.__resolv_config
        print("{} Starting TOR service...".format(self._timer))
        self.restart_tor()
        time.sleep(3)
        print("[done]")
        print("{} Setting Up Firewall Rules".format(self._timer))
        iptables = self.__set_iptables_rules(torid=torid, tport=port)
        _ = subprocess.check_output(iptables, shell=True)
        time.sleep(10)
        print("[done]")
        print("{} Checking the IP Address Obtained from TOR".format(self._timer))
        print(self.__check_ip_addr)

    def stop(self) -> None:
        print("{} STOPPING darknet.py".format(self._timer), end=" ")
        print("{} Flushing Firewall, resetting to default:\n".format(self._timer), end=" ")
        flush = self.__unset_iptables_rules()
        _ = subprocess.check_output(flush, shell=True)
        print("[done]")
        time.sleep(10)
        print("{} Reloading Network Manager".format(self._timer))
        subprocess.call(shlex.split("systemctl reload NetworkManager"))
        time.sleep(10)
        print("{} Resetting TOR Service".format(self._timer))
        self.restart_tor()
        time.sleep(1)
        print("{} Fetching current status and IP...".format(self._timer))
        print("[done]")
        print("{} CURRENT STATUS AND IP: {}".format(self._timer, self.__check_ip_addr))

    def run(self, args) -> None:
        subprocess.call(shlex.split("clear"))
        print(self.logo)
        self.__check_if_root()
        torrc = args.torrc
        port = args.port
        print("Syncing your clock...")
        self.__ntpsync()
        if args.start is True:
            print("[{}] Checking for SELinux".format(self._timer))
            print("SELinux Disabled Temporarily") if self.__sel(0) else print("SELinux not Found!")
            if args.torid is not None:
                torid = args.torid
            else:
                raise MissingTORID("Missing TOR Process ID. To get it run 'id -ur <name of your tor user>'")
            time.sleep(1)
            self.start(torid=torid, torrc=args.torrc, port=port)
        if args.stealth is True:
            print("[{}] Checking for SELinux".format(self._timer))
            print("SELinux Disabled Temporarily") if self.__sel(0) else print("SELinux not Found!")
            if args.torid is not None:
                torid = args.torid
            else:
                raise MissingTORID("Missing TOR Process ID. To get it run 'id -ur <name of your tor user>'")

            if args.ifaces is not None:
                self.__change_mac_addr([f"{interface.strip(' ')}" for interface in args.ifaces.replace("[", "").replace("]", "").split(",")])
                self.start(torid=torid, torrc=args.torrc, port=port)
            else:
                raise MissingInterfacesForStealthMode("To change mac address you need to pass a list of interfaces to the command")
        if args.stop is True:
            self.stop()
            print("[{}] Checking for SELinux...".format(self._timer))
            print("SELinux Enabled") if self.__sel(1) else print("SELinux not Found!")


if __name__ == "__main__":
    arg = parser.parse_args()
    darknet = Darknet()
    try:
        darknet.run(arg)
    except KeyboardInterrupt:
        darknet.stop()
