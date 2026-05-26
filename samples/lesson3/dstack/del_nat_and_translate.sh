ippp netns exec un0_2 ippp nat del un0 1.1.1.3 1.0.0.0/8

ippp netns exec un0_2 ip route del 1.1.1.0/25
ip netns exec un0_2 ip link set t1 down
ippp netns exec un0_2 ippp translate del t1