ippp link add h1_eth0 type veth peer name r1_eth1
ippp link add r1_eth0 type veth peer name r2_eth0
ippp link add r2_eth1 type veth peer name h2_eth0

ippp unitnet add un1 h1_eth0 r1_eth1
ippp unitnet add un0 r1_eth0 r2_eth0
ippp unitnet add un2 r2_eth1 h2_eth0

ippp unitnet setclass un1 1
ippp unitnet setclass un0 0
ippp unitnet setclass un2 1

ippp netns exec un1 ip addr add 1.1.1.1/24 dev r1_eth1
ip netns exec un1 ip link set r1_eth1 up
ip netns add un1_h
ip netns exec un1 ip link set h1_eth0 netns un1_h
ippp netns exec un1_h ip addr add 1.1.1.2/24 dev h1_eth0
ip netns exec un1_h ip link set h1_eth0 up

ippp netns exec un0 ip addr add 1.1.1.1/24 dev r1_eth0
ip netns exec un0 ip link set r1_eth0 up
ip netns add un0_1
ip netns exec un0 ip link set r2_eth0 netns un0_1
ippp netns exec un0_1 ip addr add 1.1.1.2/24 dev r2_eth0
ip netns exec un0_1 ip link set r2_eth0 up

ippp netns exec un2 ip addr add 1.1.1.1/24 dev r2_eth1
ip netns exec un2 ip link set r2_eth1 up
ip netns add un2_h
ip netns exec un2 ip link set h2_eth0 netns un2_h
ippp netns exec un2_h ip addr add 1.1.1.2/24 dev h2_eth0
ip netns exec un2_h ip link set h2_eth0 up

ippp subgateway add un0 1.1.1.1 un1 via 1.1.1.1
ippp subgateway add un0 1.1.1.2 un2 via 1.1.1.1

ip netns exec un0 sysctl net.ippp.forwarding=1
ip netns exec un0_1 sysctl net.ippp.forwarding=1
ip netns exec un1 sysctl net.ippp.forwarding=1
ip netns exec un2 sysctl net.ippp.forwarding=1