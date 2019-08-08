
# Readme

Setup tun device

``` shell
ip tuntap add tun0 mode tun
ifconfig tun0 192.168.8.1/24 up
ip route add 9.9.9.9/32 via 192.168.8.1
ip -6 route add 2018::/64 dev tun0
ip -6 addr add 2019::9.9.9.9/64 dev eth0
```

Run clat

``` shell
cd cmd/clat
go run main.go
```

Ping Test

``` shell
ping6 2019::9.9.9.9 -I tun0 -c 1
ping 9.9.9.9 -I tun0 -c 1
```

Iperf3 Test

``` shell
iperf3 -s -p 9999
iperf3 -c 2018::192.168.8.1 -p 9999 -t 30
iperf3 -c 9.9.9.9 -p 9999 -t 30
```
