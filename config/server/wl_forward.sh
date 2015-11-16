#!/bin/sh -x

sudo iptables -F FORWARD
sudo iptables -A FORWARD -o eth1 -i eth0 -s 10.5.5.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -t nat -F POSTROUTING
sudo iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE

sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

