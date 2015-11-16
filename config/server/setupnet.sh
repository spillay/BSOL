#!/bin/sh -x 
IP1=10.5.5.10
NET1=10.5.5.0/24
DEV1=eth0
GW1=10.5.5.1
#GW=192.168.6.1

IP2=10.5.7.10
NET2=10.5.7.0/24
DEV2=eth2
GW2=10.5.7.1

ip addr flush dev $DEV1
ip link set dev $DEV1 down
ip addr add $IP1 dev $DEV1
ip link set dev $DEV1 up
ip route add $NET1 dev $DEV1
#ip route add default via $GW

ip addr flush dev $DEV2
ip link set dev $DEV2 down
ip addr add $IP2 dev $DEV2
ip link set dev $DEV2 up
ip route add $NET2 dev $DEV2

ip rule add from $IP1 lookup s1
ip route add default via $GW1 table s1
ip rule add from $IP2 lookup s2
ip route add default via $GW2 table s2


