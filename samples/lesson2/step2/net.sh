ippp link add h1_eth0 type veth peer name r1_eth1
ippp link add r1_eth0 type veth peer name r2_eth1
ippp link add r2_eth0 type veth peer name br0_eth1
ippp link add r0_eth1 type veth peer name br0_eth0
ippp link add r3_eth0 type veth peer name br0_eth2
brctl addbr br0
brctl addif br0 br0_eth0
brctl addif br0 br0_eth1
brctl addif br0 br0_eth2
ippp link add r0_eth0 type veth peer name un0_eth0
ippp link add r3_eth1 type veth peer name r4_eth0
ippp link add r4_eth1 type veth peer name r5_eth0
ippp link add r5_eth1 type veth peer name h2_eth0

ippp unitnet add un0 r0_eth0 un0_eth0
ippp unitnet add un1 r0_eth1 r2_eth0 r3_eth0
ippp unitnet add un2 r2_eth1 r1_eth0
ippp unitnet add un3 r1_eth1 h1_eth0
ippp unitnet add un4 r3_eth1 r4_eth0
ippp unitnet add un5 r4_eth1 r5_eth0
ippp unitnet add un6 r5_eth1 h2_eth0

ippp unitnet setclass un0 0
ippp unitnet setclass un1 1
ippp unitnet setclass un2 2
ippp unitnet setclass un3 3
ippp unitnet setclass un4 2
ippp unitnet setclass un5 3
ippp unitnet setclass un6 4

ippp netns exec un0 ip addr add 1.1.1.1/24 dev r0_eth0
ip netns exec un0 ip link set r0_eth0 up
ip netns add un0_1
ip netns exec un0 ip link set un0_eth0 netns un0_1
ippp netns exec un0_1 ip addr add 1.1.1.2/24 dev un0_eth0
ip netns exec un0_1 ip link set un0_eth0 up

ippp netns exec un1 ip addr add 1.1.1.1/24 dev r0_eth1
ip netns exec un1 ip link set r0_eth1 up
ip netns add un1_1
ip netns exec un1 ip link set r2_eth0 netns un1_1
ippp netns exec un1_1 ip addr add 1.1.1.2/24 dev r2_eth0
ip netns exec un1_1 ip link set r2_eth0 up
ip netns add un1_2
ip netns exec un1 ip link set r3_eth0 netns un1_2
ippp netns exec un1_2 ip addr add 1.1.1.3/24 dev r3_eth0
ip netns exec un1_2 ip link set r3_eth0 up
ip link set br0 up
ip link set br0_eth0 up
ip link set br0_eth1 up
ip link set br0_eth2 up

ippp netns exec un2 ip addr add 1.1.1.2/24 dev r1_eth0
ip netns exec un2 ip link set r1_eth0 up
ip netns add un2_1
ip netns exec un2 ip link set r2_eth1 netns un2_1
ippp netns exec un2_1 ip addr add 1.1.1.1/24 dev r2_eth1
ip netns exec un2_1 ip link set r2_eth1 up

ippp netns exec un3 ip addr add 1.1.1.1/24 dev r1_eth1
ip netns exec un3 ip link set r1_eth1 up
ip netns add un3_h
ip netns exec un3 ip link set h1_eth0 netns un3_h
ippp netns exec un3_h ip addr add 1.1.1.2/24 dev h1_eth0
ip netns exec un3_h ip link set h1_eth0 up

ippp netns exec un4 ip addr add 1.1.1.1/24 dev r3_eth1
ip netns exec un4 ip link set r3_eth1 up
ip netns add un4_1
ip netns exec un4 ip link set r4_eth0 netns un4_1
ippp netns exec un4_1 ip addr add 1.1.1.2/24 dev r4_eth0
ip netns exec un4_1 ip link set r4_eth0 up

ippp netns exec un5 ip addr add 1.1.1.1/24 dev r4_eth1
ip netns exec un5 ip link set r4_eth1 up
ip netns add un5_1
ip netns exec un5 ip link set r5_eth0 netns un5_1
ippp netns exec un5_1 ip addr add 1.1.1.2/24 dev r5_eth0
ip netns exec un5_1 ip link set r5_eth0 up

ippp netns exec un6 ip addr add 1.1.1.1/24 dev r5_eth1
ip netns exec un6 ip link set r5_eth1 up
ip netns add un6_h
ip netns exec un6 ip link set h2_eth0 netns un6_h
ippp netns exec un6_h ip addr add 1.1.1.2/24 dev h2_eth0
ip netns exec un6_h ip link set h2_eth0 up


ippp subgateway add un0 1.1.1.1 un1 via 1.1.1.1
ippp subgateway add un1 1.1.1.2 un2 via 1.1.1.1
ippp subgateway add un2 1.1.1.2 un3 via 1.1.1.1
ippp subgateway add un1 1.1.1.3 un4 via 1.1.1.1
ippp subgateway add un4 1.1.1.2 un5 via 1.1.1.1
ippp subgateway add un5 1.1.1.2 un6 via 1.1.1.1

ip netns exec un1_1 sysctl net.ippp.forwarding=1
ip netns exec un1_2 sysctl net.ippp.forwarding=1
ip netns exec un2 sysctl net.ippp.forwarding=1
ip netns exec un2_1 sysctl net.ippp.forwarding=1
ip netns exec un3 sysctl net.ippp.forwarding=1
ip netns exec un4 sysctl net.ippp.forwarding=1
ip netns exec un4_1 sysctl net.ippp.forwarding=1
ip netns exec un5 sysctl net.ippp.forwarding=1
ip netns exec un5_1 sysctl net.ippp.forwarding=1
ip netns exec un6 sysctl net.ippp.forwarding=1