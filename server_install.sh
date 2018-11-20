#!/bin/bash
# 
# Description: This script installs the necessary dependencies for obtserver

echo "Updating system"
apt-get update
echo "Installing python3, python3-dev, python3-pip, and git"
apt-get install python3 python3-dev python3-pip git
echo "Installing pwntools for Python3"
pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git
if [ ! -d ~/Repos ]; then
	echo "Creating directory ~/Repos"
	mkdir ~/Repos
fi
echo "Installing requests lib"
pip3 install requests
cd ~/Repos
echo "Cloning radare2"
git clone https://github.com/radare/radare2.git
echo "Installing radare2"
./radare2/sys/install.sh
echo "Installing complete!"
