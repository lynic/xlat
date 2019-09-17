
# Readme

Run xlat from code

``` shell
cd cmd/main
sudo env "PATH=$PATH" env "GOPATH=$GOPATH" env "XLATCONF=$(pwd)/../config.yml" go run main.go
```

Run xlat through docker

``` shell
docker run -it --privileged=true --network=host -v $(pwd)/cmd/config.yml:/etc/xlat/config.yml elynn/nat64:latest
```

Config route rules

``` shell
ip -6 addr add 2019::9.9.9.9/64 dev eth0
```

Ping Test

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

pprof

``` shell
go tool pprof http://127.0.0.1:6060/debug/pprof/profile
```
