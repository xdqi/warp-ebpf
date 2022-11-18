What
--------------------------

A tc-bpf action to rewrite `wg.reserved_zero[3]` to `client_id` required by warp, and vice versa for ingress.

Usage
--------------------------

* Register with `warp-register.py` first, save the result into `/etc/wireguard/cf.conf`
* Replace in `warp-ebpf.c`:
  * Find the line `static const __u8 warp_private[3] = {11, 45, 14};`
  * Change `{11, 45, 14}` to the content of `ClientID` in `cf.conf` above
* `make` to build the eBPF module
* `./attach.sh <your network interface>` to load it into your system
* `wg-quick up cf` start the wireguard tunnel
* `./detach.sh` to remove it from your system

TODO
--------------------------

* IPv6 support

Credits
--------------------------
* [Ritare/1919](https://github.com/Riatre/1919): eBPF example
* [iBug/warp-helper](https://gist.github.com/iBug/3107fd4d5af6a4ea7bcea4a8090dcc7e): original wg-warp-helper
* [Wireguard Protocol](https://www.wireguard.com/protocol/): Wireguard protocol specification
