#!/bin/sh

iptables -A INPUT -p udp -j NFQUEUE --dport 1024:65535 --queue-num 0 --queue-bypass
