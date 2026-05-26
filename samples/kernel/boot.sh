qemu-system-x86_64 \
  -kernel ./linux-6.18.3/arch/x86_64/boot/bzImage \
  -drive file=../buildroot/buildroot-2025.02/output/images/rootfs.ext4 \
  -virtfs local,path=../shared,mount_tag=host0,security_model=passthrough,id=host0 \
  -append "root=/dev/sda console=ttyS0 nokaslr noapic" \
  -serial stdio \
  -s \
  -S \
  -net nic -net tap,ifname=tap0,script=no,downscript=no

p *mod->sect_attrs->attrs@20
add-symbol-file ../../shared/ippp.ko -s .text 18446744072101040128 -s .init.text 18446744072101212160 -s .exit.text 18446744072101132608 -s .rodata 18446744072101183712

b tcp_pp_connect
b inet_hash_connect
b tcp_pp_conn_request
b tcp_conn_request
b tcp_pp_send_synack
b ippp_route_input_noref
b ippp_route_output_flow
b ip_route_output_flow
b tcp_ack
b ippp_rcv
b tcp_pp_rcv
b tcp_pp_do_rcv
b tcp_rcv_state_process
b tcp_pp_rcv_state_process
b tcp_pp_syn_recv_sock
b __inet_lookup
b tcp_pp_route_req
b __ip_route_output_key
b ip_route_output_key_hash_rcu
b inetpp_sendmsg
b tcp_recvmsg
b ippp_local_out
b tcp_pp_send_reset
