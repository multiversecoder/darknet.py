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
        $ darknet.py --start --torid <YOUR_TOR_ID>

    normal mode outside 5,9,14 eyes
        $ darknet.py --start --torid <YOUR_TOR_ID> --no5
        $ darknet.py --start --torid <YOUR_TOR_ID> --no9
        $ darknet.py --start --torid <YOUR_TOR_ID> --no14
        $ darknet.py --start --torid <YOUR_TOR_ID> --no14p

    stealth mode
        $ darknet.py --stealth --torid <YOUR_TOR_ID> --ifaces [enp1s0]

    stealth mode outside 5,9,14 eyes
        $ darknet.py --stealth --torid <YOUR_TOR_ID> --ifaces [enp1s0] --no5
        $ darknet.py --stealth --torid <YOUR_TOR_ID> --ifaces [enp1s0] --no9
        $ darknet.py --stealth --torid <YOUR_TOR_ID> --ifaces [enp1s0] --no14
        $ darknet.py --stealth --torid <YOUR_TOR_ID> --ifaces [enp1s0] --no14p

    stopping
        $ darknet.py --stop

    uninstall
        $ darknet.py --remove


NOTES:
    <interface(s)> should be added as python list [wlo1, ...]

DISCLAIMER:
    The author of this software assumes no responsibility for the use of this
    software to perform actions that do not comply with the law or damage
    property or individuals.
    Using this software you take full responsibility for your actions.
"""

parser = argparse.ArgumentParser(usage=USAGE)
parser.add_argument(
    "--start", help="Starts the transparent proxy", action="store_true")
parser.add_argument(
    "--stealth", help="Changes MAC Address and Starts the transparent proxy",
    action="store_true")
parser.add_argument(
    "--stop", help="Stop the execution and reset configurations",
    action="store_true")
parser.add_argument(
    "--torrc", help="The location of torrc config file", type=str)
parser.add_argument("--torid", help="The TOR Process ID", type=int)
parser.add_argument("--tpass", help="The TOR Control Password (Enables Control)", type=str)
parser.add_argument("--port", help="The tor service port", type=int)
parser.add_argument(
    "--ifaces", help="Add interfaces to change MAC Address", type=str)
parser.add_argument(
    "--remove",
    help="Removes the current installation of darknet.py from the system",
    action="store_true")
parser.add_argument(
    "--no5", help="Excludes Nodes from 5 eyes countries", action="store_true")
parser.add_argument(
    "--no9", help="Excludes Nodes from 9 eyes countries", action="store_true")
parser.add_argument(
    "--no14", help="Excludes Nodes from 14 eyes countries", action="store_true")
parser.add_argument(
    "--no14p",
    help="Excludes Nodes from 14 eyes countries + Others",
    action="store_true")

COUNTRIES = "{AF},{AX},{AL},{DZ},{AD},{AO},{AI},{AQ},{AG},{AR},{AM},{AW},{AU},{AT},{AZ},{BS},{BH},{BD},{BB},{BY},{BE},{BZ},{BJ},{BM},{BT},{BO},{BA},{BW},{BV},{BR},{IO},{VG},{BN},{BG},{BF},{BI},{KH},{CM}, {CA},{CV},{KY},{CF},{TD},{CL},{CN},{CX},{CC},{CO},{KM},{CG},{CD},{CK},{CR},{CI},{HR},{CU},{CY},{CZ},{DK},{DJ},{DM},{DO},{EC},{EG},{SV},{GQ},{EE},{ET},{FK},{FO},{FJ},{FI},{FR},{GF},{PF},{TF},{GA},{GM},{GE},{DE},{GH},{GI},{GR},{GL},{GD},{GP},{GU},{GT},{GN},{GW},{GY},{HT},{HM},{HN},{HK},{HU},{IS},{IN},{ID},{IR},{IQ},{IE},{IM},{IL},{IT},{JM},{JP},{JO},{KZ},{KE},{KI},{KP},{KR},{KW},{KG},{LA},{LV},{LB},{LS},{LR},{LY},{LI},{LT},{LU},{MO},{MK},{MG},{MW},{MY},{MV},{ML},{MT},{MH},{MQ},{MR},{MU},{YT},{MX},{FM},{MD},{MC},{MN},{ME},{MS},{MA},{MZ},{MM},{NA},{NR},{NP},{NL},{NC},{NZ},{NI},{NE},{NG},{NU},{NF},{MP},{NO},{OM},{PK},{PW},{PS},{PA},{PG},{PY},{PE},{PH},{PN},{PL},{PT},{PR},{QA},{RE},{RO},{RU},{RW},{WS},{SM},{ST},{SA},{SN},{RS},{SC},{SL},{SG},{SK},{SI},{SB},{SO},{AS},{ZA},{GS},{ES},{LK},{SH},{KN},{LC},{PM},{VC},{SD},{SR},{SJ},{SZ},{SE},{CH},{SY},{TW},{TJ},{TZ},{TH},{TG},{TK},{TO},{TT},{TN},{TR},{TM},{TC},{TV},{UG},{UA},{AE},{GB},{US},{UM},{UY},{UZ},{VU},{VA},{VE},{VN},{VI},{WF},{EH},{YE},{ZM},{ZW}" #noqa

NO5EYES = COUNTRIES.replace("{US},", "").replace("{GB},", "").replace(
    "{AU},", "").replace("{CA},", "").replace("{NZ},", "")

NO9EYES = NO5EYES.replace("{FR},", "").replace(
    "{DK},", "").replace("{NO},", "").replace("{NL},", "")

NO14EYES = NO9EYES.replace("{BE},", "").replace(
    "{IT},", "").replace("{ES},", "").replace("{DE},", "").replace("{SE},", "")

NO14EYESPLUS = NO14EYES.replace("{JP},", "").replace(
    "{CN},", "").replace("{KP},", "").replace(
    "{KR},", "").replace("{IL},", "").replace("{SG},", "")


class PermissionDenied(Exception):
    pass


class TORNotInstalled(Exception):
    pass


class NMNotInstalled(Exception):
    pass


class CURLNotInstalled(Exception):
    pass


class MissingTORID(Exception):
    pass


class MissingInterfacesForStealthMode(Exception):
    pass


class UnsupportedOS(Exception):
    pass


class Darknet:

    def __init__(self):
        self.logo = """
            ___           _               _
           /   \__ _ _ __| | ___ __   ___| |_
          / /\ / _` | '__| |/ / '_ \ / _ \ __|
         / /_// (_| | |  |   <| | | |  __/ |_
        /___,' \__,_|_|  |_|\_\_| |_|\___|\__| .py

        v1.1 - https://github.com/multiversecode/darknet.py
        Using this software you take full responsibility for your actions
        run darknet.py -h to see help, full disclaimer or usage
        """
        self.__check_if_linux()
        self.__check_if_tor_installed()
        self.__check_if_curl_installed()
        self.__check_if_nm_installed()
        signal.signal(signal.SIGINT, self.__handle_sigint)

    def __check_if_root(self) -> None:
        """
        Checks if user is root

        Returns
        -------
            None

        Raises
        ------
            PermissionDenied if user is not root
        """
        if os.getuid() != 0:
            raise PermissionDenied("You must be root to run this program")

    def __check_if_linux(self) -> None:
        """
        Checks if the script runs under Linux

        Returns
        -------
            None

        Raises
        ------
            UnsupportedOS if is not linux
        """
        if "linux" not in sys.platform:
            raise UnsupportedOS("You need a Linux distro to run this program")

    def __ip4f(self) -> None:
        """
        Disables Kernel IP Forwarding

        Returns
        -------
            None

        """
        subprocess.call(shlex.split("sysctl -w net.ipv4.ip_forward=0"))

    def __icmp(self) -> None:
        """
        Sets ignore to all icmp echo packets in Kernel

        Returns
        -------
            None
        """
        subprocess.call(shlex.split(
            "sysctl -w net.ipv4.icmp_echo_ignore_all=1"))

    def __mtp(self) -> None:
        subprocess.call(shlex.split("sysctl -w net.ipv4.tcp_mtu_probing=1"))

    def __sel(self, en: int) -> bool:
        """
        Sets SELinux Status (if Installed) calling setenforce 0|1

        Parameters
        ----------
            en : int = 1 to enable | 0 to disable

        Returns
        -------
            bool: True if setenforce is installed else False
        """
        if bool(shutil.which("setenforce")) is not False:
            subprocess.call(shlex.split("setenforce {}".format(en)))
            return True
        return False

    def __check_if_tor_installed(self) -> None:
        """
        Checks if TOR is Installed using shutil.which

        Returns
        -------
            None

        Raises
        ------
            TORNotInstalled if TOR package is not installed
        """
        if bool(shutil.which("tor")) is False:
            raise TORNotInstalled(
                "TOR not installed... Please install TOR")

    def __check_if_nm_installed(self) -> None:
        """
        Checks if NetworkManager is Installed using shutil.which

        Returns
        -------
            None

        Raises
        ------
            NMNotInstalled if NetworkManager package is not installed
        """
        if bool(shutil.which("NetworkManager")) is False:
            raise TORNotInstalled(
                "NetworkManager not installed... Please install NetworkManager")

    def __check_if_curl_installed(self) -> None:
        """
        Checks if CURL is Installed using shutil.which

        Returns
        -------
            None

        Raises
        ------
            CURLNotInstalled if CURL package is not installed
        """
        if bool(shutil.which("curl")) is False:
            raise CURLNotInstalled(
                "CURL not installed... Please install CURL")

    def __handle_sigint(self, signum, frame):
        """
        Handles signal interruption

        Returns
        -------
            None
        """
        print('\nKeyBoard Interrupt Detected\nShutting Down Darknet\n')
        print("{} [info] shutting down darknet.py\n\n".format(self._timer))
        self.stop()
        sys.exit(1)

    @property
    def __has_internet_connection(self) -> bool:
        """
        Checks if connection is up

        Returns
        -------
            bool = True if ok else False
        """
        while True:
            try:
                urlopen('https://check.torproject.org/', timeout=1)
                return True
            except:
                continue
            break

    @property
    def __check_ip_addr(self)-> str:
        """
        Checks the IP Address of your Workstation/Server
        If TOR is enabled checks https://check.torproject.org
        else https://ipinfo.io/ip

        Returns
        -------
            str = IP Address
        """

        if self.__has_internet_connection and self.has_tor:
            return "TOR is enabled\n {}".format(
                subprocess.getoutput(
                    "curl -s https://check.torproject.org/ | cat | grep -m 1 IP | xargs | sed 's/<[^>]*>//g'")
            )
        elif self.__has_internet_connection and not self.has_tor:
            return "TOR is disabled\nYour IP address appears to be: {}".format(
                subprocess.getoutput("curl -s https://ipinfo.io/ip"))

    @property
    def _timer(self) -> str:
        """
        Returns
        -------
            str = Current Time in Hours:Minutes:Seconds
        """
        return "[{}]".format(time.strftime('%H:%M:%S', time.localtime()))


    def __set_iptables_rules(self, torid: int, tport: int = None,
        nontor: str = "0.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 192.88.99.0/24 198.18.0.0/15 198.51.100.0/24") -> str:
        """
        Sets IPTables Rules for Transparent Proxy
        This method should be passed to subprocess.check_output

        Parameters
        ----------
            torid:  int = TOR user ID
            tport:  int = TOR transport Port
            nontor: str = All Address that should be not routed wth TOR

        Returns
        -------
            str = IPTables Commands
        """
        return """
        /usr/sbin/iptables -F
        /usr/sbin/iptables -t nat -F
        /usr/sbin/iptables -t nat -A OUTPUT -m owner --uid-owner {torid} -j RETURN
        /usr/sbin/iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A OUTPUT -o lo -j ACCEPT
        for NET in {nontor}; do
            /usr/sbin/iptables -t nat -A OUTPUT -d $NET -j RETURN
        done
        /usr/sbin/iptables -t nat -A OUTPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports {tport}
        /usr/sbin/iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
        /usr/sbin/iptables -A OUTPUT -p icmp --icmp-type echo-request -j DROP
        /usr/sbin/iptables -A INPUT -m state --state RELATED -j DROP
        /usr/sbin/iptables -A OUTPUT -m state --state RELATED -j DROP
        /usr/sbin/iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
        for NET in {nontor}; do
            /usr/sbin/iptables -A OUTPUT -d $NET -j ACCEPT
        done
        /usr/sbin/iptables -A OUTPUT -m owner --uid-owner {torid} -j ACCEPT
        /usr/sbin/iptables -A OUTPUT -j DROP
        """.format(
            torid=torid,
            tport=tport if tport is not None else 9040,
            nontor=nontor)

    def __unset_iptables_rules(self) -> str:
        """
        Reset all IPTables Rules
        This method should be passed to subprocess.check_output

        Returns
        -------
            str = IPTABles Commands
        """
        return """
            /usr/sbin/iptables -P INPUT ACCEPT
            /usr/sbin/iptables -P FORWARD ACCEPT
            /usr/sbin/iptables -P OUTPUT ACCEPT
            /usr/sbin/iptables -t nat -F
            /usr/sbin/iptables -t mangle -F
            /usr/sbin/iptables -F
            /usr/sbin/iptables -X
        """

    def __gen_tpass(self, psw: str) -> str:
        """
        Generates a TOR Control Password

        Parameters
        ----------
            psw: str = Plain Text Password

        Returns
        -------
            str = Hashed Password using --hash-password command from TOR
        """
        return subprocess.check_output(
            shlex.split(
                "tor --hash-password {psw}".format(
                    psw=psw))).decode("utf-8").split("\n")[-2:-1][0]


    def __torrc_file(self, tport: int, cs: str, tpass: str) -> str:
        """
        Generates a Secure TORRC Configuration File

        Parameters
        ----------
            tport:  int = The TOR Transport Port
            cs:     str = Country List
            tpass:  str = The Hashed Password For TOR Control

        Returns
        -------
            str = The TORRC File that should be saved on /etc/tor/torrc

        """
        print("Exit Nodes from 14 eyes countries are blocked by default")
        return inspect.cleandoc("""
        # THIS FILE IS GENERATED BY
        #       DARKNET.PY
        AvoidDiskWrites 1
        GeoIPExcludeUnknown 1
        SocksPort 127.0.0.1:9050 IsolateDestAddr IsolateDestPort
        SocksPort 127.0.0.1:9150 IsolateSOCKSAuth KeepAliveIsolateSOCKSAuth
        {tc}
        VirtualAddrNetworkIPv4 10.0.0.0/10
        AutomapHostsOnResolve 1
        AutomapHostsSuffixes .exit,.onion
        ExcludeExitNodes {{us}},{{au}},{{ca}},{{nz}},{{gb}},{{fr}},{{sg}},{{jp}},{{kp}},{{se}},{{il}},{{es}},{{it}},{{no}},{{dk}},{{nl}},{{be}}
        NodeFamily {cs}
        StrictNodes 1
        TransPort {tport} IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
        DNSPort 5353
        WarnPlaintextPorts 23,109,110,143
        PathsNeededToBuildCircuits 0.95
        IPv6Exit 0
        """.format(
                tport=tport if tport is not None else 9040,
                cs=cs if cs is not None else COUNTRIES,
                tc=inspect.cleandoc("""
                    ControlPort 9052
                    CookieAuthentication 1
                    HashedControlPassword {tpass}
                    """.format(
                    tpass=self.__gen_tpass(tpass))
                ) if tpass is not None else ""))

    @property
    def __random_mac_address(self) -> str:
        """
        Generates a Random Unicast MAC Address

        Returns
        -------
            str = The New Random MAC Address
        """
        return "02:00:00:%02x:%02x:%02x" % (
            random.randint(0, 255), random.randint(
                0, 255), random.randint(0, 255))

    def __change_mac_addr(self, interfaces: list) -> None:
        """
        Changes MAC Address in every Network Interface passed
        interfaces param
        This command use /usr/sbin/ip to modify interfaces

        Parameters
        ----------
            interfaces : List[str] = List of interfaces ([wlo2, ensp1o,...])

        Returns
        -------
            None
        """
        print("{} Changing MAC Addresses...".format(self._timer))
        for interface in interfaces:
            print("{} Changing: {}".format(self._timer, interface))
            subprocess.call(shlex.split(
                "/sbin/ip link set {} down".format(interface)))
            time.sleep(5)
            macaddr = self.__random_mac_address
            subprocess.call(shlex.split(
                "/sbin/ip link set {} address {}".format(interface, macaddr)))
            time.sleep(5)
            subprocess.call(shlex.split(
                "/sbin/ip link set {} up".format(interface)))
            print("{} MAC Addresses changed for interface: {} => {} ".format(
                self._timer, interface, macaddr))
            print("{} Reloading Network Manager".format(self._timer))
            subprocess.call(shlex.split("systemctl reload NetworkManager"))
            time.sleep(10)
        print("[done]")

    def __set_torrc_config(self, torrc_content: str) -> None:
        """
        Saves TORRC Content into /etc/tor/torrc

        Parameters
        ----------
            torrc_content : str = The TORRC gen by self.__torrc_file

        Returns
        -------
            None
        """
        with open("/etc/tor/torrc", "w") as torrc:
            print("{} Configuring torrc file... ".format(self._timer, end=""))
            torrc.write(torrc_content)
        print("[done]")

    def __open_user_torrc_config(self, torrc_location: str) -> str:
        with open(torrc_location, "r") as torrc:
            torrc = torrc.read()
        return torrc

    def __backup_old_torrc(self) -> str:
        if not os.path.exists("/etc/tor/torrc.orig"):
            with open("/etc/tor/torrc.orig", "w+") as torrc_orig:
                torrc_orig.write(
                    self.__open_user_torrc_config("/etc/tor/torrc"))

    def __torrc_config(self, torrc: str, tport: int = None, cs: str = None,
        tpass: str = None) -> None:
        """
        Configures the new TORRC File
        Backups Original TORRC File found in /etc/tor

        Parameters
        ----------
            tport:  int = The TOR Transport Port
            cs:     str = Country List
            tpass:  str = The Hashed Password For TOR Control

        Returns
        -------
            None
        """
        torrc = self.__open_user_torrc_config(
            torrc) if torrc is not None else self.__torrc_file(
            tport, cs, tpass)
        with open("/etc/tor/torrc") as torrc_old:
            torrc_old = torrc_old.read()
        if torrc == torrc_old:
            print("{} torrc file already configured".format(self._timer))
        else:
            print(
                "{} Backup torrc file => /etc/tor/torrc.orig".format(
                    self._timer))
            self.__backup_old_torrc()
            self.__set_torrc_config(torrc)

    def __torrc_reset(self) -> None:
        """
        Removes Generated TORRC Content
        Restore TORRC File found in /etc/tor/ before darknet.py

        Returns
        -------
            None
        """
        with open("/etc/tor/torrc.orig") as ot:
            with open("/etc/tor/torrc", "w") as nt:
                nt.write(ot.read())

    @property
    def __resolv_config(self) -> None:
        """
        Changes resolv.conf to Prevent DNS Leaks

        Returns
        -------
            None
        """
        with open("/etc/resolv.conf") as resolv_conf:
            resolv_conf = resolv_conf.read()
        if resolv_conf == "nameserver 127.0.0.1":
            print("{} DNS resolv.conf file already configured".format(
                self._timer))
        else:
            self.__set_resolv_config("nameserver 127.0.0.1")

    def __set_resolv_config(self, resolv_content: str) -> None:
        """
        This file (resolv.conf) is resetted when Restarting
        the sys w/o darknet.py
        """
        with open("/etc/resolv.conf", "w") as resolvconf:
            print("{} Configuring DNS resolv.conf file.. ".format(
                self._timer), end="")
            resolvconf.write(resolv_content)
            print("[done]")

    @property
    def has_tor(self) -> bool:
        """
        Checks if "Congratulations" appears in check.torproject.org

        Returns
        -------
            bool = True if "Congratulations" else False
        """
        status_message = subprocess.getoutput(
            "curl -s https://check.torproject.org/ | cat | grep -m 1 Congratulations | xargs")
        if "Congratulations" in status_message:
            return True
        return False


    def restart_tor(self) -> None:
        subprocess.call(shlex.split("systemctl restart tor.service"))

    def start(self, torid: int, torrc: str = None, port: int = None, cs: str = None,
        tpass: str = None) -> None:

        print("Hardering System...")
        self.__ip4f()
        self.__icmp()
        self.__mtp()
        print("{} Checking for SELinux".format(self._timer))
        print("SELinux Disabled Temporarily") if self.__sel(
            0) else print("SELinux not Found!")
        self.__torrc_config(torrc, port, cs, tpass)
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
        print(
            "{} Checking the IP Address Obtained from TOR".format(
                self._timer))
        print(self.__check_ip_addr)

    def stop(self) -> None:
        print("{} STOPPING darknet.py".format(self._timer), end=" ")
        print("\n{} Flushing Firewall, resetting to default:\n".format(
            self._timer), end=" ")
        flush = self.__unset_iptables_rules()
        _ = subprocess.check_output(flush, shell=True)
        print("[done]")
        time.sleep(10)
        print("{} Reloading Network Manager".format(self._timer))
        subprocess.call(shlex.split("systemctl reload NetworkManager"))
        time.sleep(10)
        print("{} Resetting TOR Service".format(self._timer))
        self.__torrc_reset()
        self.restart_tor()
        time.sleep(1)
        print("{} Fetching current status and IP...".format(self._timer))
        print("[done]")
        print("{} CURRENT STATUS AND IP: {}".format(
            self._timer, self.__check_ip_addr))
        print("{} Checking for SELinux...".format(self._timer))
        print("SELinux Enabled") if self.__sel(
            1) else print("SELinux not Found!")
        print(
            "darknet.py disabled. You may need to Restart your Machine to revert some changes!")

    def run(self, args) -> None:
        subprocess.call(shlex.split("clear"))

        print(self.logo)

        self.__check_if_root()

        if args.start is True:

            if args.torid is not None:
                torid = args.torid
            else:
                raise MissingTORID(
                "Missing TOR Process ID. To get it run '$ id -u <name of your TOR user>'")

            # Sets Countries and other things and start

            if args.no5 is True:
                print("Running darknet.py outside 5 eyes countries")
                self.start(torid=torid, torrc=args.torrc, port=args.port,
                           cs=NO5EYES, tpass=args.tpass)

            elif args.no9 is True:
                print("Running darknet.py outside 9 eyes countries")
                self.start(torid=torid, torrc=args.torrc, port=args.port,
                           cs=NO9EYES, tpass=args.tpass)

            elif args.no14 is True:
                print("Running darknet.py outside 14 eyes countries")
                self.start(torid=torid, torrc=args.torrc, port=args.port,
                           cs=NO14EYES, tpass=args.tpass)

            elif args.no14p is True:
                print("Running darknet.py outside 14+ eyes countries")
                self.start(torid=torid, torrc=args.torrc, port=args.port,
                           cs=NO14EYESPLUS, tpass=args.tpass)
            else:
                self.start(torid=torid, torrc=args.torrc, port=args.port,
                           cs=COUNTRIES, tpass=args.tpass)

        if args.stealth is True:

            if args.torid is not None:
                torid = args.torid
            else:
                raise MissingTORID(
                "Missing TOR Process ID. To get it run '$ id -u <name of your TOR user>'")

            if args.ifaces is not None:
                self.__change_mac_addr(
                    [f"{interface.strip(' ')}" for interface in args.ifaces.replace(
                        "[", "").replace("]", "").split(",")])

                # Sets Countries and other things and start

                if args.no5 is True:
                    print("Running darknet.py outside 5 eyes countries")
                    self.start(torid=torid, torrc=args.torrc, port=args.port,
                               cs=NO5EYES, tpass=args.tpass)

                elif args.no9 is True:
                    print("Running darknet.py outside 9 eyes countries")
                    self.start(torid=torid, torrc=args.torrc, port=args.port,
                               cs=NO9EYES, tpass=args.tpass)

                elif args.no14 is True:
                    print("Running darknet.py outside 14 eyes countries")
                    self.start(torid=torid, torrc=args.torrc, port=args.port,
                               cs=NO14EYES, tpass=args.tpass)

                elif args.no14p is True:
                    print("Running darknet.py outside 14+ eyes countries")
                    self.start(torid=torid, torrc=args.torrc, port=args.port,
                               cs=NO14EYESPLUS, tpass=args.tpass)

                else:
                    self.start(torid=torid, torrc=args.torrc, port=args.port,
                               cs=COUNTRIES, tpass=args.tpass)
            else:
                raise MissingInterfacesForStealthMode(
                "To change MAC you need to pass interfaces")

        if args.stop is True:
            self.stop()

        if args.remove is True:
            print("{} Uninstalling darknet.py...".format(self._timer))
            subprocess.call(shlex.split("rm /usr/local/bin/darknet.py"))
            print("darknet.py Sucessfully Uninstalled...")


if __name__ == "__main__":
    arg = parser.parse_args()
    darknet = Darknet()
    try:
        darknet.run(arg)
    except KeyboardInterrupt:
        darknet.stop()
