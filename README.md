
# Readme

Run clat

``` shell
cd cmd/plat
sudo env "PATH=$PATH" env "GOPATH=$GOPATH" env "XLATCONF=$(pwd)/../config.json" go run main.go
```

Config route rules

``` shell
# ip tuntap add tun0 mode tun
# ifconfig tun0 192.168.8.1/24 up
# ip route add 9.9.9.9/32 via 192.168.8.1
# ip -6 route add 2018::/64 dev tun0
ip -6 addr add 2019::9.9.9.9/64 dev eth0
# ip -6 addr add 2019::2/64 dev eth0
```

Clat Ping Test

``` shell
ping6 2018::192.168.8.1 -I tun0 -c 1
ping 9.9.9.9 -I tun0 -c 1
ping6 2017::192.168.8.1 -I tun0 -c 1
```

Iperf3 Test

``` shell
iperf3 -s -p 9999
iperf3 -c 2018::192.168.8.1 -p 9999 -t 30
iperf3 -c 9.9.9.9 -p 9999 -t 30
iperf3 -c 2017::192.168.8.1 -p 9999 -t 30
```

Clean

``` shell
ip tuntap del tun0 mode tun
```

pprof

``` shell
go tool pprof http://127.0.0.1:6060/debug/pprof/profile
```
