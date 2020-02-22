#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "To install darknet.py must be run as root"
   exit 1
fi
echo "Installing darknet.py"
echo "Checking NetworkManager Requirement"
if which NetworkManager; then
	echo "NetworkManager Installed"
	echo "Checking Tor Requirement"
	if which tor; then
	    echo 'Tor is Installed'
	    echo "Installing darknet.py"
	    python3 ./setup.py install
	    echo "Sucessfully Installed!"
	    echo "Run darknet.py --start --torid <YOUR_TOR_ID> to start darknet.py!"
	    darknet.py -h
	else
	    echo "Tor is not Installed"
	    echo "Install Tor With your preferred package manager"
	fi
else
	echo "NetworkManager not found on this system."
	echo "Install NetworkManager and retry the installation"
fi
