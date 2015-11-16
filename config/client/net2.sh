#!/bin/sh -x

IP1=10.5.4.10
NET1=10.5.4.0/24
DEV1=eth1
GW1=10.5.4.1

IP2=10.5.6.10
NET2=10.5.6.0/24
DEV2=eth3
GW2=10.5.6.1


ip rule add from $IP1 lookup s1
ip route add default via $GW1 table s1
ip rule add from $IP2 lookup s2
ip route add default via $GW2 table s2
