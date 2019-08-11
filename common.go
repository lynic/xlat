package xlat

import "net"

func CopyIP(ip net.IP) net.IP {
	addr := make([]byte, len(ip))
	copy(addr, ip)
	return addr
}
