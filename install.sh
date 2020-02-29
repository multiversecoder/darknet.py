#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "To install darknet.py must be run as root"
   exit 1
fi
echo "Installing darknet.py v1.1"
echo "Checking NetworkManager Requirement"
if which NetworkManager; then
	echo "NetworkManager [OK]"
	echo "Checking IPTables Requirement"	
	if which iptables; then
		echo "IPTables [OK]"
		echo "Checking Python3 Requirement"	
		if which python3; then
			echo "python3 [OK]"
			echo "Checking cURL Requirement"
			if which curl; then
				echo "cURL [OK]"
				echo "Checking Tor Requirement"
				if which tor; then
					echo 'Tor [OK]'
					echo "Installing darknet.py"
					python3 ./setup.py install
					echo "darknet.py Sucessfully Installed!"
					echo "Run darknet.py --start --torid <YOUR_Tor_ID> to start darknet.py now!"
					darknet.py -h
					echo "Check https://github.com/multiversecoder/darknet.py for more information"
				else
					echo "Tor is not Installed"
					echo "Install Tor and retry the installation"
				fi
			else
				echo "cURL not Installed"
				echo "Install cURL and retry the installation"
			fi
		else
			echo "Python3 not Installed"
			echo "Install Python3 and retry the installation"
		fi
	else
		echo "IPTables not Installed"
		echo "Install IPTables and retry the installation"
	fi
else
	echo "NetworkManager not installed"
	echo "Install NetworkManager and retry the installation"
fi
