ippp netns exec un2 ippp translate add t0 ipv4 link r2_eth1
ip netns exec un2 ip link set t0 up
ippp netns exec un2 ip route add 1.1.1.0/25 dev t0