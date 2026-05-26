ippp link add h1_eth0 type veth peer name br0_eth0
ippp link add h2_eth0 type veth peer name br0_eth1
ippp link add r1_eth0 type veth peer name br0_eth2
brctl addbr br0
brctl addif br0 br0_eth0
brctl addif br0 br0_eth1
brctl addif br0 br0_eth2
ippp link add r1_eth1 type veth peer name h3_eth0

ippp unitnet add un0 h1_eth0 h2_eth0 r1_eth0
ippp unitnet add un1 r1_eth1 h3_eth0

ippp unitnet setclass un0 0
ippp unitnet setclass un1 1

ippp netns exec un0 ip addr add 1.1.1.1/24 dev h1_eth0
ip netns exec un0 ip link set h1_eth0 up
ip netns add un0_1
ip netns exec un0 ip link set h2_eth0 netns un0_1
ippp netns exec un0_1 ip addr add 1.1.1.2/24 dev h2_eth0
ip netns exec un0_1 ip link set h2_eth0 up
ip netns add un0_2
ip netns exec un0 ip link set r1_eth0 netns un0_2
ippp netns exec un0_2 ip addr add 1.1.1.3/24 dev r1_eth0
ip netns exec un0_2 ip link set r1_eth0 up
ip link set br0 up
ip link set br0_eth0 up
ip link set br0_eth1 up
ip link set br0_eth2 up

ippp netns exec un1 ip addr add 1.1.1.1/24 dev r1_eth1
ip netns exec un1 ip link set r1_eth1 up
ip netns add un1_1
ip netns exec un1 ip link set h3_eth0 netns un1_1
ippp netns exec un1_1 ip addr add 1.1.1.2/24 dev h3_eth0
ip netns exec un1_1 ip link set h3_eth0 up

ippp subgateway add un0 1.1.1.3 un1 via 1.1.1.1

ip netns exec un0 sysctl net.ippp.forwarding=1
ip netns exec un0_1 sysctl net.ippp.forwarding=1
ip netns exec un0_2 sysctl net.ippp.forwarding=1
ip netns exec un1 sysctl net.ippp.forwarding=1
ip netns exec un1_1 sysctl net.ippp.forwarding=1