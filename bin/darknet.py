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
        $ darknet.py --start --torid <YOUR_Tor_ID>

    normal mode outside 5,9,14 eyes
        $ darknet.py --start --torid <YOUR_Tor_ID> --no5
        $ darknet.py --start --torid <YOUR_Tor_ID> --no9
        $ darknet.py --start --torid <YOUR_Tor_ID> --no14
        $ darknet.py --start --torid <YOUR_Tor_ID> --no14p

    stealth mode
        $ darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0]

    stealth mode outside 5,9,14 eyes
        $ darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0] --no5
        $ darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0] --no9
        $ darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0] --no14
        $ darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0] --no14p

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
parser.add_argument("--torid", help="The Tor Process ID", type=int)
parser.add_argument("--tpass", help="The Tor Control Password (Enables Control)", type=str)
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
    "--no14", help="Excludes Nodes from 14 eyes countries",
    action="store_true")
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


class TorNotInstalled(Exception):
    pass


class NMNotInstalled(Exception):
    pass


class CURLNotInstalled(Exception):
    pass


class MissingTorID(Exception):
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
        self.__check_if_root()
        self.__check_if_linux()
        self.__check_if_tor_installed()
        self.__check_if_curl_installed()
        self.__check_if_nm_installed()
        self.__assign()
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

    def __assign(self) -> None:
        """

        """
        self.ipt_loc = shutil.which("iptables")
        self.ipbin = shutil.which("ip")

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
    
    def __noipv6(self) -> None:
        """
        Disables Kernel IPv6 Forwarding

        Returns
        -------
            None

        """
        subprocess.call(shlex.split("sysctl -w net.ipv6.conf.all.disable_ipv6=1"))
        subprocess.call(shlex.split("sysctl -w net.ipv6.conf.default.disable_ipv6=1"))
        subprocess.call(shlex.split("sysctl -w net.ipv6.conf.lo.disable_ipv6=1"))
    

    def __noip4ts(self) -> None:
        """
        Disables Kernel IPv4 TCP Timestamps

        Returns
        -------
            None
        """
        subprocess.call(shlex.split("sysctl -w net.ipv4.tcp_timestamps=0"))


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
        Checks if Tor is Installed using shutil.which

        Returns
        -------
            None

        Raises
        ------
            TorNotInstalled if Tor package is not installed
        """
        if bool(shutil.which("tor")) is False:
            raise TorNotInstalled(
                "Tor not installed... Please install Tor")

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
            raise NMNotInstalled(
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
        If Tor is enabled checks https://check.torproject.org
        else https://ipinfo.io/ip

        Returns
        -------
            str = IP Address
        """

        if self.__has_internet_connection and self.has_tor:
            return "Tor is enabled\n {}".format(
                subprocess.getoutput(
                    "curl -s https://check.torproject.org/ | cat | grep -m 1 IP | xargs | sed 's/<[^>]*>//g'")
            )
        elif self.__has_internet_connection and not self.has_tor:
            return "Tor is disabled\nYour IP address appears to be: {}".format(
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
            torid:  int = Tor user ID
            tport:  int = Tor transport Port
            nontor: str = All Address that should be not routed wth Tor

        Returns
        -------
            str = IPTables Commands
        """

        return """
        {ipt_loc} -F
        {ipt_loc} -t nat -F
        {ipt_loc} -t nat -A OUTPUT -m owner --uid-owner {torid} -j RETURN
        {ipt_loc} -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353
        {ipt_loc} -A INPUT -i lo -j ACCEPT
        {ipt_loc} -A OUTPUT -o lo -j ACCEPT
        for NET in {nontor}; do
            {ipt_loc} -t nat -A OUTPUT -d $NET -j RETURN
        done
        {ipt_loc} -t nat -A OUTPUT -p tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports {tport}
        {ipt_loc} -A INPUT -p icmp --icmp-type echo-request -j DROP
        {ipt_loc} -A OUTPUT -p icmp --icmp-type echo-request -j DROP
        {ipt_loc} -A INPUT -m state --state RELATED -j DROP
        {ipt_loc} -A OUTPUT -m state --state RELATED -j DROP
        {ipt_loc} -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
        for NET in {nontor}; do
            {ipt_loc} -A OUTPUT -d $NET -j ACCEPT
        done
        {ipt_loc} -A OUTPUT -m owner --uid-owner {torid} -j ACCEPT
        {ipt_loc} -A OUTPUT -j DROP
        """.format(
            torid=torid,
            tport=tport if tport is not None else 9040,
            nontor=nontor,
            ipt_loc=self.ipt_loc)

    def __unset_iptables_rules(self) -> str:
        """
        Reset all IPTables Rules
        This method should be passed to subprocess.check_output

        Returns
        -------
            str = IPTABles Commands
        """
        return """
            {ipt_loc} -P INPUT ACCEPT
            {ipt_loc} -P FORWARD ACCEPT
            {ipt_loc} -P OUTPUT ACCEPT
            {ipt_loc} -t nat -F
            {ipt_loc} -t mangle -F
            {ipt_loc} -F
            {ipt_loc} -X
        """.format(ipt_loc=self.ipt_loc)

    def __gen_tpass(self, psw: str) -> str:
        """
        Generates a Tor Control Password

        Parameters
        ----------
            psw: str = Plain Text Password

        Returns
        -------
            str = Hashed Password using --hash-password command from Tor
        """
        return subprocess.check_output(
            shlex.split(
                "tor --hash-password {psw}".format(
                    psw=psw))).decode("utf-8").split("\n")[-2:-1][0]


    def __torrc_file(self, tport: int, cs: str, tpass: str) -> str:
        """
        Generates a Secure torrc Configuration File

        Parameters
        ----------
            tport:  int = The Tor Transport Port
            cs:     str = Country List
            tpass:  str = The Hashed Password For Tor Control

        Returns
        -------
            str = The torrc File that should be saved on /etc/tor/torrc

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
                tc=inspect.cleandoc(
                    """
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
        This command use ip command to modify interfaces

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
                "{ipbin} link set {iface} down".format(ipbin=self.ipbin, iface=interface)))
            time.sleep(5)
            macaddr = self.__random_mac_address
            subprocess.call(shlex.split(
                "{ipbin} link set {iface} address {mac}".format(ipbin=self.ipbin, iface=interface, mac=macaddr)))
            time.sleep(5)
            subprocess.call(shlex.split(
                "{ipbin} link set {iface} up".format(ipbin=self.ipbin, iface=interface)))
            print("{} MAC Addresses changed for interface: {} => {} ".format(
                self._timer, interface, macaddr))
            print("{} Reloading NetworkManager".format(self._timer))
            subprocess.call(shlex.split("systemctl reload NetworkManager"))
            time.sleep(10)
        print("[done]")

    def __set_torrc_config(self, torrc_content: str) -> None:
        """
        Saves torrc Content into /etc/tor/torrc

        Parameters
        ----------
            torrc_content : str = The torrc gen by self.__torrc_file

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
        Configures the new torrc File
        Backups Original torrc File found in /etc/tor

        Parameters
        ----------
            tport:  int = The Tor Transport Port
            cs:     str = Country List
            tpass:  str = The Hashed Password For Tor Control

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
        Removes Generated torrc Content
        Restore torrc File found in /etc/tor/ before darknet.py

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

    def start(self, args) -> None:

        print("Hardering System...")
        self.__ip4f()
        self.__noip4ts()
        self.__noipv6()
        self.__icmp()
        self.__mtp()
        print("{} Checking for SELinux".format(self._timer))
        print("SELinux Disabled Temporarily") if self.__sel(
            0) else print("SELinux not Found!")

        if args.no5 is True:
            self.__torrc_config(args.torrc, args.port, NO5EYES, args.tpass)
        elif args.no9 is True:
            self.__torrc_config(args.torrc, args.port, NO9EYES, args.tpass)
        elif args.no14 is True:
            self.__torrc_config(args.torrc, args.port, NO14EYES, args.tpass)
        elif args.no14p is True:
            self.__torrc_config(
                args.torrc, args.port, NO14EYESPLUS, args.tpass)
        else:
            self.__torrc_config(args.torrc, args.port, COUNTRIES, args.tpass)

        self.__resolv_config
        print("{} Starting Tor service...".format(self._timer))
        self.restart_tor()
        time.sleep(3)
        print("[done]")
        print("{} Setting Up Firewall Rules".format(self._timer))
        iptables = self.__set_iptables_rules(torid=args.torid, tport=args.port)
        _ = subprocess.check_output(iptables, shell=True)
        time.sleep(10)
        print("[done]")
        print(
            "{} Checking the IP Address Obtained from Tor".format(
                self._timer))
        print(self.__check_ip_addr)
        print(inspect.cleandoc(
            """
            \033[1;31mWarning:\033[0m

                If you plan to browse the web using darknet.py and Tor using a common browser
                YOU NEED to disable WebRTC to prevent potential leaks of your real IP Address.
                
            \033[1;33mAdvices:\033[0m:

                1 => Do not use Chrome because there are no official methods to
                     disable WebRTC
                
                2 => Use Firefox or an alternative that supports disabling WebRTC

            Firefox Solution:

                1 => Visit "about:config" from the address bar and hit Enter
                2 => Click on "I Accept the risk"
                3 => Type "media.peerconnection.enabled" in the search bar
                4 => Set the value to false
            """
        ))

    def stop(self) -> None:
        print("{} STOPPING darknet.py".format(self._timer), end=" ")
        print("\n{} Flushing Firewall, resetting to default:\n".format(
            self._timer), end=" ")
        flush = self.__unset_iptables_rules()
        _ = subprocess.check_output(flush, shell=True)
        print("[done]")
        time.sleep(10)
        print("{} Reloading NetworkManager".format(self._timer))
        subprocess.call(shlex.split("systemctl reload NetworkManager"))
        time.sleep(10)
        print("{} Resetting Tor Service".format(self._timer))
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
            "darknet.py disabled. You may need to reboot your system to revert some changes!")

    def run(self, args) -> None:
        subprocess.call(shlex.split("clear"))

        print(self.logo)

        if args.start is True:

            if args.torid is None:
                raise MissingTorID(
                "Missing Tor Process ID. To get it run '$ id -u <name of your Tor user>'")

            self.start(args)

        if args.stealth is True:

            if args.torid is None:
                raise MissingTorID(
                "Missing Tor Process ID. To get it run '$ id -u <name of your Tor user>'")

            if args.ifaces is not None:
                self.__change_mac_addr(
                    [f"{interface.strip(' ')}" for interface in args.ifaces.replace(
                        "[", "").replace("]", "").split(",")])
            else:
                raise MissingInterfacesForStealthMode(
                "To change MAC you need to pass interfaces")

            self.start(args)

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
