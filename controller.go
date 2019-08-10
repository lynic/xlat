package xlat

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
)

// type PortType uint16
// type IP4Key uint32

var Ctrl *Controller

type NATuple struct {
	IP   net.IP
	Port uint16
}

func (t *NATuple) Copy() *NATuple {
	newt := &NATuple{
		IP:   make([]byte, len(t.IP)),
		Port: t.Port,
	}
	copy(newt.IP, t.IP)
	return newt
}

type PortPool struct {
	// PortMap map[uint16]*NATuple
	PortMap sync.Map
}

// type SessionPool struct {

// 	SessionMap map[uint16]
// }

type Controller struct {
	Table64 map[string]net.IP
	// Table46 map[uint32]*PortPool
	Table46 sync.Map
}

func (pp *PortPool) Init() error {
	// pp.PortMap = make(map[uint16]*NATuple)
	return nil
}

func (pp *PortPool) Get(port uint16) *NATuple {
	// if _, exist := pp.PortMap[port]; exist == false {
	// 	return nil
	// }
	// return pp.PortMap[port]
	v, ok := pp.PortMap.Load(port)
	if ok == false {
		return nil
	}
	return v.(*NATuple).Copy()
}

func (pp *PortPool) Set(port uint16, ip6t *NATuple) error {
	// pp.PortMap[port] = ip6t
	e := pp.Get(port)
	if e != nil && e.IP.Equal(ip6t.IP) && e.Port == ip6t.Port {
		return nil
	}
	pp.PortMap.Store(port, ip6t)
	return nil
}

func (c *Controller) Init() error {
	c.InitTable()
	return nil
}

func (c *Controller) InitTable() {
	poolStart := binary.BigEndian.Uint32(ConfigVar.Plat.Src.IP)
	poolEnd := binary.BigEndian.Uint32(ConfigVar.Plat.Src.IP)
	prefix, _ := ConfigVar.Plat.Src.Mask.Size()
	poolEnd |= uint32(0xffffffff) >> uint(prefix)
	// poolSize := int(poolEnd-poolStart) + 1
	// c.Table46 = make(map[uint32]*PortPool, poolSize)
	for i := poolStart; i <= poolEnd; i++ {
		pp := &PortPool{}
		err := pp.Init()
		if err != nil {
			log.Printf("failed to init %d pool: %s", i, err.Error())
		}
		// c.Table46[i] = pp
		c.Table46.Store(i, pp)
	}
}

func (c *Controller) SetTable(ip4t *NATuple, ip6t *NATuple) error {
	// c.Table46[binary.BigEndian.Uint32(ip4t.IP)].Set(ip4t.Port, ip6t)
	// key := binary.BigEndian.Uint32(ip4t.IP)
	v, _ := c.Table46.Load(binary.BigEndian.Uint32(ip4t.IP))
	pp := v.(*PortPool)
	pp.Set(ip4t.Port, ip6t)
	return nil
}

func (c *Controller) AllocIP(ip6t *NATuple) *NATuple {
	ip4 := HashIP(ip6t.IP)
	ip4t := &NATuple{
		IP:   ip4,
		Port: ip6t.Port,
	}
	// log.Printf("saved ip6t %v", nip6t)
	// c.Table46[binary.BigEndian.Uint32(ip4)].Set(ip4t.Port, nip6t)
	c.SetTable(ip4t, ip6t.Copy())
	return ip4t
}

func (c *Controller) GetIP(ip4t *NATuple) *NATuple {
	// return c.Table46[binary.BigEndian.Uint32(ip4t.IP)].Get(ip4t.Port)
	v, _ := c.Table46.Load(binary.BigEndian.Uint32(ip4t.IP))
	pp := v.(*PortPool)
	return pp.Get(ip4t.Port)
}

func HashIP(srcIP net.IP) net.IP {
	pool := ConfigVar.Plat.Src
	ip := net.IPv4(0, 0, 0, 0).To4()
	for i := 0; i < len(srcIP); i += 4 {
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
