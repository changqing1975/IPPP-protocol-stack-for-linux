#!/bin/bash
brctl addbr br0
brctl stp br0 off
brctl setfd br0 1
brctl sethello br0 1
ifconfig br0 10.0.2.1/24 promisc up
tunctl -t tap0 -u root
brctl addif br0 tap0
ifconfig tap0 0.0.0.0 promisc up

# sysctl net.ipv4.conf.all.forwarding=1
# iptables -P FORWARD ACCEPT
# iptables -t nat -A POSTROUTING -s 10.0.2.0/24 ! -o br0 -j MASQUERADE
# # ping 192.168.0.101
#
# iptables -P INPUT ACCEPT
# iptables -P OUTPUT ACCEPT
# iptables -t nat -A PREROUTING ! -i br0 -p tcp -m tcp --dport 8088 -j DNAT --to-destination 10.0.2.2:80
# nc -lp 80
# --------------------------------------------------------------------------------
# QEMU
# ifconfig eth0 10.0.2.2 netmask 255.255.255.0 up
# route add default gw 10.0.2.1 eth0

# ip addr add 10.0.2.2/24 dev eth0
# ip link set dev eth0 up
# ip route add default via 10.0.2.1

# /etc/resolv.conf
# nameserver 114.114.114.114
