ippp unitnet add un1 enp0s3

ippp netns exec un1 ip addr add 192.168.0.101/24 dev enp0s3 # 192.168.0.102
ip netns exec un1 ip link set enp0s3 up

ip netns exec un1 sysctl net.ippp.forwarding=1