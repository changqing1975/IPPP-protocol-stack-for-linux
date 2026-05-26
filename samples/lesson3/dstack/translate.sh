ippp netns exec un0_2 ippp translate add t1 ipv4 link r1_eth0
ip netns exec un0_2 ip link set t1 up
ippp netns exec un0_2 ip route add 1.1.1.0/25 dev t1