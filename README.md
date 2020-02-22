# darknet.py - Network Anonymization Tool

## What is darknet.py
darknet.py is a network application with no dependencies other than Python and TOR, to anonymize the traffic of linux servers and workstations. 

The action darknet.py performs is to redirect all traffic via SOCKS5 (TOR) Proxy.

DNS requests are also anonymized and darknet.py makes DNSLeak almost impossible.

## Requirements
To run darknet.py you need TOR.

Install TOR with your package manager.

NetworkManager is a mandatory requirement for the use of darknet.py

Install NetworkManager with your package manager.

## How Can I Install darknet.py on Linux?
Download

`git clone https://github.com/multiversecoder/darknet.py `

`cd darknet.py`

In the darknet.py folder use the ./install.sh to install the software

`chmod +x install.sh`

`sudo ./install.sh`

## Usage

usage: 

    normal mode
    
       ./darknet --start --torid 104
    
    stealth mode
    
        ./darknet --stealth --torid 104 --ifaces [enp1s0]
    
    stopping
    
        ./darknet --stop

NOTES:
    
    <interface(s)> should be added as python list [wlo1, ...]

DISCLAIMER:
    
    The author of this software assumes no responsibility for the use of this software to perform actions that do not comply with the law or damage property or individuals.
    Using this software you take full responsibility for your actions.

optional arguments:
  
  -h, --help       show this help message and exit

  --start          Starts the transparent proxy

  --stealth        Changes MAC Address and Starts the transparent proxy

  --stop           Stop the execution and reset configurations

  --torrc TORRC    The location of torrc config file

  --torid TORID    The TOR Process ID

  --port PORT      The tor service port

  --ifaces IFACES  Add interfaces to change mac address
