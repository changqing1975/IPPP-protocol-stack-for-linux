ippp link add h1_eth0 type veth peer name r1_eth1

ippp unitnet add un1 h1_eth0 r1_eth1
ippp unitnet add un0 enp0s3

ippp unitnet setclass un1 1
ippp unitnet setclass un0 0

ippp netns exec un1 ip addr add 1.1.1.1/24 dev r1_eth1
ip netns exec un1 ip link set r1_eth1 up
ip netns add un1_h
ip netns exec un1 ip link set h1_eth0 netns un1_h
ippp netns exec un1_h ip addr add 1.1.1.2/24 dev h1_eth0
ip netns exec un1_h ip link set h1_eth0 up

ippp netns exec un0 ip addr add 192.168.0.101/24 dev enp0s3
ip netns exec un0 ip link set enp0s3 up

ippp subgateway add un0  192.168.0.101 un1 via 1.1.1.1

ip netns exec un0 sysctl net.ippp.forwarding=1
ip netns exec un1 sysctl net.ippp.forwarding=1