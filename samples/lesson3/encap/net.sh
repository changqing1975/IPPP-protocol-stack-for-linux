ippp link add h1_eth0 type veth peer name r1_eth0
ippp link add r1_eth1 type veth peer name r2_eth0
ippp link add r2_eth1 type veth peer name r3_eth0
ippp link add r3_eth1 type veth peer name h2_eth0

ippp unitnet add un0 h1_eth0 r1_eth0 r1_eth1 r2_eth0 r2_eth1 r3_eth0 r3_eth1 h2_eth0

ippp unitnet setclass un0 1

ip netns add ns_h1
ip netns exec un0 ip link set h1_eth0 netns ns_h1
ippp netns exec ns_h1 ip addr add 192.168.1.1/24 dev h1_eth0
ip netns exec ns_h1 ip link set h1_eth0 up

ip netns add ns_r1
ip netns exec un0 ip link set r1_eth0 netns ns_r1
ippp netns exec ns_r1 ip addr add 192.168.1.2/24 dev r1_eth0
ip netns exec ns_r1 ip link set r1_eth0 up
ip netns exec un0 ip link set r1_eth1 netns ns_r1
ippp netns exec ns_r1 ip addr add 192.168.2.1/24 dev r1_eth1
ip netns exec ns_r1 ip link set r1_eth1 up

ip netns add ns_r2
ip netns exec un0 ip link set r2_eth0 netns ns_r2
ippp netns exec ns_r2 ip addr add 192.168.2.2/24 dev r2_eth0
ip netns exec ns_r2 ip link set r2_eth0 up
ip netns exec un0 ip link set r2_eth1 netns ns_r2
ippp netns exec ns_r2 ip addr add 192.168.3.1/24 dev r2_eth1
ip netns exec ns_r2 ip link set r2_eth1 up

ip netns add ns_r3
ip netns exec un0 ip link set r3_eth0 netns ns_r3
ippp netns exec ns_r3 ip addr add 192.168.3.2/24 dev r3_eth0
ip netns exec ns_r3 ip link set r3_eth0 up
ip netns exec un0 ip link set r3_eth1 netns ns_r3
ippp netns exec ns_r3 ip addr add 192.168.4.1/24 dev r3_eth1
ip netns exec ns_r3 ip link set r3_eth1 up

ip netns add ns_h2
ip netns exec un0 ip link set h2_eth0 netns ns_h2
ippp netns exec ns_h2 ip addr add 192.168.4.2/24 dev h2_eth0
ip netns exec ns_h2 ip link set h2_eth0 up

ip netns exec ns_h1 ip route add default via 192.168.1.2
ip netns exec ns_r1 ip route add 192.168.0.0/16 via 192.168.2.2
ip netns exec ns_r2 ip route add 192.168.1.0/24 via 192.168.2.1
ip netns exec ns_r2 ip route add 192.168.4.0/24 via 192.168.3.2
ip netns exec ns_r3 ip route add 192.168.0.0/16 via 192.168.3.1
ip netns exec ns_h2 ip route add default via 192.168.4.1

ip netns exec ns_r1 sysctl net.ipv4.conf.all.forwarding=1
ip netns exec ns_r2 sysctl net.ipv4.conf.all.forwarding=1
ip netns exec ns_r3 sysctl net.ipv4.conf.all.forwarding=1

ip netns exec ns_r1 sysctl net.ippp.forwarding=1
# ip netns exec ns_r2 sysctl net.ippp.forwarding=1
ip netns exec ns_r3 sysctl net.ippp.forwarding=1