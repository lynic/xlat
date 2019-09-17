package plat

import (
	"encoding/binary"
	"net"
	"xlat"
)

// type PortType uint16
// type IP4Key uint32

var PlatController *Controller

type NATuple struct {
	IP   net.IP
	Port uint16
}

type PortPool struct {
	PortMap map[uint16]*NATuple
}

// type SessionPool struct {

// 	SessionMap map[uint16]
// }

type Controller struct {
	Table64 map[string]net.IP
	Table46 map[uint32]*PortPool
}

func (pp *PortPool) Init() error {
	for i := uint16(0); i < 0xffff; i++ {
		pp.PortMap[i] = nil
	}
	return nil
}

func (pp *PortPool) Set(port uint16, ip6t *NATuple) error {
	// return pp.PortMap[port]
	pp.PortMap[port] = ip6t
	return nil
}

func (c *Controller) Init() error {
	c.InitTable()
	return nil
}

func (c *Controller) InitTable() {
	poolStart := binary.LittleEndian.Uint32(xlat.ConfigVar.Plat.Src.IP)
	poolEnd := binary.LittleEndian.Uint32(xlat.ConfigVar.Plat.Src.IP)
	prefix, _ := xlat.ConfigVar.Plat.Src.Mask.Size()
	poolEnd |= uint32(0xffffffff) >> uint(prefix)
	poolSize := int(poolEnd-poolStart) + 1
	c.Table46 = make(map[uint32]*PortPool, poolSize)
	for i := poolStart; i <= poolEnd; i++ {
		pp := &PortPool{}
		pp.Init()
		c.Table46[i] = pp
	}
}

func (c *Controller) SetTable(ip4t *NATuple, ip6t *NATuple) error {
	c.Table46[binary.LittleEndian.Uint32(ip4t.IP)].Set(ip4t.Port, ip6t)
	return nil
}

func (c *Controller) AllocIP(ip6t *NATuple) *NATuple {
	ip4 := HashIP(ip6t.IP)
	ip4t := &NATuple{
		IP:   ip4,
		Port: ip6t.Port,
	}
	c.Table46[binary.LittleEndian.Uint32(ip4)].Set(ip4t.Port, ip6t)
	return ip4t
}

func HashIP(srcIP net.IP) net.IP {
	pool := xlat.ConfigVar.Plat.Src
	ip := net.IPv4(0, 0, 0, 0).To4()
	for i := 0; i < len(srcIP); i *= 4 {
		ip[0] ^= srcIP[i+0]
		ip[1] ^= srcIP[i+1]
		ip[2] ^= srcIP[i+2]
		ip[3] ^= srcIP[i+3]
	}
	prefix, _ := pool.Mask.Size()
	i := 0
	for prefix > 8 {
		ip[i] = pool.IP[i]
		i++
		prefix -= 8
	}
	if prefix > 0 {
		ip[i] &= byte(0xff) >> uint(prefix)
		ip[i] |= pool.IP[i] & (byte(0xff) << uint(8-prefix))
	}
	return ip
}

func ConvertPacket(p *xlat.Packet) (*xlat.Packet, error) {
	if len(p.Layers) == 1 {
		p.LazyLayers()
	}
	var err error
	for i := len(p.Layers) - 1; i >= 0; i-- {
		switch p.Layers[i].Type {
		case xlat.LayerTypeICMPv4:
			p, err = xlat.ICMP4ToICMP6(p)
			if err != nil {
				return nil, err
			}
		case xlat.LayerTypeIPv4:
			p, err = xlat.IP4ToIP6(p)
			if err != nil {
				return nil, err
			}
		case xlat.LayerTypeICMPv6:
			p, err = xlat.ICMP6ToICMP4(p)
			if err != nil {
				return nil, err
			}
		case xlat.LayerTypeIPv6:
			p, err = xlat.IP6ToIP4(p)
			if err != nil {
				return nil, err
			}
		}
	}
	for i := len(p.Layers) - 1; i >= 0; i-- {
		p.Layers[i].CalcChecksum(p)
	}
	return p, nil
}
