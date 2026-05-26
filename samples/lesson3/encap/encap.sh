ippp netns exec ns_r1 ippp encap add encap0 link r1_eth1
ip netns exec ns_r1 ip link set encap0 up
ippp netns exec ns_r1 ip route add 192.168.4.0/24 dev encap0

ippp netns exec ns_r3 ippp encap add encap1 link r3_eth0
ip netns exec ns_r3 ip link set encap1 up
ippp netns exec ns_r3 ip route add 192.168.1.0/24 dev encap1