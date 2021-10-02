**This repository has been archived as it was poorly developed during a very confusing time.**

For a better version: [hidemego](https://github.com/multiversecoder/hidemego)

# darknet.py - Network Anonymization Tool 

## What is darknet.py?

darknet.py is a network application with no dependencies other than Python and Tor, useful to anonymize the traffic of linux servers and workstations. 

The action darknet.py performs is to redirect all traffic via SOCKS5 (Tor) Proxy using the Transparent Proxy Method.

DNS requests are also anonymized and darknet.py makes DNS Leak almost impossible.

## When to use darknet.py?

darknet.py can be used under any circumstances that require a mandatory anonymity requirement. The cases could be different: From Scraping to the prevention of attacks on Servers with Critical Information, or the communication in total anonymity through the programs of daily use.

The creator's hope is that it will be used to improve people's privacy.

It is up to the user to decide what to do with it.

## Compatibility

The compatibility of darknet.py is verified on all RHEL distributions such as Fedora and CentOS. Debian/Ubuntu/Mint are also supported.

SELinux is temporarily disabled when darknet.py is started.

## Requirements

To use darknet.py you need a Linux distribution with:

- Python3.7
- Tor
- NetworkManager
- IPTables
- CURL

## How Can I Install darknet.py on Linux?
Download

`$ git clone https://github.com/multiversecoder/darknet.py `

`$ cd darknet.py`

In the darknet.py folder use the ./install.sh to install the software

`$ chmod +x install.sh`

`$ sudo ./install.sh`

## Features

- Ease of use
- MAC address spoofing
- Compatibility with Linux Distros
- Security against DNS Leaks
- No need to use external libraries (Python)

## Usage

To start darknet.py without special configurations use the command:
    
`$ sudo darknet.py --start --torid <YOUR_Tor_ID>`
    
To start darknet.py in stealth mode to change the MAC Address of the interfaces, use the command:
    
`$ sudo darknet.py --stealth --torid <YOUR_Tor_ID> --ifaces [enp1s0]`
    
To end the darknet.py anonymisation session, use the command:

`$ sudo darknet.py --stop`

NOTES:
    
    <interface(s)> should be added as python list [wlo1, ...]


## Optional darknet.py arguments:
  
  -h, --help | show this help message and exit

  --start | Starts the transparent proxy

  --stealth | Changes MAC Address and Starts the transparent proxy

  --stop | Stop the execution and reset configurations

  --torrc TorRC | Sets the location of torrc config file

  --torid TorID | Sets the Tor Process ID
  
  --tpass TPASS | The Tor Control Password (Enables Control Port)

  --port PORT | Sets the Tor transport port

  --ifaces IFACES | Add interfaces to change mac address
  
  --remove | Removes the current installation of darknet.py from the system
  
  --no5 | Excludes Nodes from 5 eyes countries
  
  --no9 | Excludes Nodes from 9 eyes countries
  
  --no14 | Excludes Nodes from 14 eyes countries
  
  --no14p | Excludes Nodes from 14 eyes countries + Others
  
## Finding your Tor ID

From the terminal run:
    
`id -u (Tor username)`
    
Finding ID of Default Tor User on RHEL/CentOS/Fedora:

`id -u toranon`

Finding ID of Default Tor User on Debian/Ubuntu/Mint:

`id -u debian-tor`

Finding ID of Default Tor User on ARCH:

`id -u tor`

## DISCLAIMER:
    
The author of this software assumes no responsibility for the use of this software to perform actions that do not comply with the law or damage property or individuals.
Using this software you take full responsibility for your actions.
