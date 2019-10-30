#!/bin/bash

export ROOT_ID=0

EXEC_DIR=/usr/bin

abort_root()
{
    echo -e "\e[33mRun it as root!\e[0m"
    exit 2
}

if [ "$UID" -ne "$ROOT_ID" ]; then
    abort_root
fi

# install needed packages
sudo apt install libpcap-dev
sudo apt install libnet-dev

cd src;
gcc -Wall main.c arpspoof.c arp.c sleep.c net.c output.c error.c -o $EXEC_DIR/aspoof -lnet -lpcap -pthread
