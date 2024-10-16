#!/bin/sh

sudo iptables -A INPUT -p icmp -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0
