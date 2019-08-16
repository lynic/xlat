package xlat

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"xlat/dns"
	"xlat/radvd"

	"github.com/spaolacci/murmur3"
)

// type PortType uint16
// type IP4Key uint32

const (
	NATDirection46 = "46"
	NATDirection64 = "64"
)

var Ctrl *Controller

type NATuple struct {
	// IP       net.IP
	// Port     uint16
	IP4       net.IP
	Port4     uint16
	IP6       net.IP
	Port6     uint16
	LastUsed  time.Time
	Direction string
	Mux       *sync.Mutex
}

func (t *NATuple) Init() error {
	t.Mux = &sync.Mutex{}
	return nil
}

func (t *NATuple) Copy() *NATuple {
	newt := &NATuple{
		Port4:     t.Port4,
		Port6:     t.Port6,
		LastUsed:  t.LastUsed,
		Direction: t.Direction,
		Mux:       t.Mux,
	}
	if t.IP4 != nil {
		newt.IP4 = make([]byte, len(t.IP4))
		copy(newt.IP4, t.IP4)
	}
	if t.IP6 != nil {
		newt.IP6 = make([]byte, len(t.IP6))
		copy(newt.IP6, t.IP6)
	}
	return newt
}

func (t *NATuple) CopyTo(ipt *NATuple) *NATuple {
	// newt := &NATuple{
	// 	Port4:     t.Port4,
	// 	Port6:     t.Port6,
	// 	LastUsed:  t.LastUsed,
	// 	Direction: t.Direction,
	// 	Mux:       t.Mux,
	// }
	ipt.Port4 = t.Port4
	ipt.Port6 = t.Port6
	ipt.LastUsed = t.LastUsed
	ipt.Direction = t.Direction
	if ipt.Mux == nil {
		ipt.Mux = t.Mux
	}
	if t.IP4 != nil && ipt.IP4 == nil {
		ipt.IP4 = make([]byte, len(t.IP4))
		copy(ipt.IP4, t.IP4)
	}
	if t.IP6 != nil && ipt.IP6 == nil {
		ipt.IP6 = make([]byte, len(t.IP6))
		copy(ipt.IP6, t.IP6)
	}
	return ipt
}

// type SessionPool struct {

// 	SessionMap map[uint16]
// }

type Controller struct {
	Table64 map[string]net.IP
	// Table46 map[uint32]*PortPool
	// Table46 sync.Map
	Table46 map[uint32]*PortPool
	Mux46   map[uint32]*sync.Mutex
}

type PortPool struct {
	// PortMap map[uint16]*NATuple
	PortMap sync.Map
	// Mux     map[uint16]*sync.Mutex
	Mux sync.Map
}

func (pp *PortPool) Init() error {
	// pp.PortMap = make(map[uint16]*NATuple)
	// pp.Mux = make(map[uint16]*sync.Mutex)
	return nil
}

func (pp *PortPool) Get(ipt *NATuple) *NATuple {
	// if _, exist := pp.PortMap[port]; exist == false {
	// 	return nil
	// }
	// return pp.PortMap[port]
	v, ok := pp.PortMap.Load(ipt.Port4)
	if ok == false {
		return nil
	}
	out := v.(*NATuple)
	out.LastUsed = time.Now()
	if !out.IP4.Equal(ipt.IP4) {
		log.Printf("Not Match! in.IP4 = %s, out.IP4 = %s", ipt.IP4, out.IP4)
	}
	if out.Port4 != ipt.Port4 {
		log.Printf("Not Match! in.Port4 = %d, out.Port4 = %d", ipt.Port4, out.Port4)
	}
	ipt.IP6 = CopyIP(out.IP6)
	ipt.Port6 = out.Port6
	return ipt
}

func (pp *PortPool) Set(ipt *NATuple) error {
	// pp.PortMap[port] = ip6t
	e := pp.Get(ipt)
	if e != nil && e.IP6.Equal(ipt.IP6) && e.Port6 == ipt.Port6 {
		return nil
	}
	pp.PortMap.Store(ipt.Port4, ipt)
	return nil
}

func (pp *PortPool) GetAndSet(ipt *NATuple) {
	// first time, port4 == port6
	// other time, port4++
	// v, ok := pp.Mux.LoadOrStore(ipt.Port4, &sync.Mutex{})
	// lock := v.(*sync.Mutex)
	nipt := &NATuple{}
	// nipt.Init()
	v, ok := pp.PortMap.LoadOrStore(ipt.Port4, nipt)
	if ok {
		// replace record
		// lock.Lock()
		t := v.(*NATuple)
		if t.Mux == nil {
			log.Printf("Race condition waiting for mutex: %+v", ipt)
			for t.Mux == nil {
			}
			pp.GetAndSet(ipt)
			return
		}
		t.Mux.Lock()
		// v, _ := pp.PortMap.Load(ipt.Port4)
		// t := v.(*NATuple)
		if t.IP6.Equal(ipt.IP6) {
			t.LastUsed = time.Now()
			// lock.Unlock()
			t.Mux.Unlock()
		} else if time.Since(t.LastUsed).Minutes() > ConfigVar.Spec.NATTimeout {
			log.Printf("ipt timeout %+v", t)
			t.IP6 = CopyIP(ipt.IP6)
			t.LastUsed = time.Now()
			// lock.Unlock()
			t.Mux.Unlock()
		} else {
			log.Printf("ipt conflict t=%+v, ipt=%+v", t, ipt)
			// lock.Unlock()
			t.Mux.Unlock()
			ipt.Port4++
			if ipt.Port4 >= 60000 {
				ipt.Port4 = 10000
			}
			pp.GetAndSet(ipt)
		}
	} else {
		// no record
		t := v.(*NATuple)
		t.Init()
		t.Mux.Lock()
		// ipt.Port4 = ipt.Port4
		ipt.LastUsed = time.Now()
		ipt.CopyTo(t)
		// ipt.Mux = t.Mux
		// pp.PortMap.Store(ipt.Port4, ipt.Copy())
		t.Mux.Unlock()
	}
}

func (c *Controller) Init() error {
	c.InitTable()
	return nil
}

func (c *Controller) InitTable() {
	c.Table46 = make(map[uint32]*PortPool, len(ConfigVar.Plat.Src))
	for _, ip := range ConfigVar.Plat.Src {
		pp := &PortPool{}
		err := pp.Init()
		if err != nil {
			log.Printf("failed to init table %s: %s", ip.String(), err.Error())
		}
		// c.Table46.Store(binary.BigEndian.Uint32(ip), pp)
		c.Table46[binary.BigEndian.Uint32(ip)] = pp
	}
}

// func (c *Controller) SetTable(ipt *NATuple) error {
// 	// c.Table46[binary.BigEndian.Uint32(ip4t.IP)].Set(ip4t.Port, ip6t)
// 	// key := binary.BigEndian.Uint32(ip4t.IP)
// 	// v, _ := c.Table46.Load(binary.BigEndian.Uint32(ipt.IP4))
// 	// pp := v.(*PortPool)
// 	pp := c.Table46[binary.BigEndian.Uint32(ipt.IP4)]
// 	pp.GetAndSet(ipt)
// 	return nil
// }

func (c *Controller) AllocIP(ipt *NATuple) *NATuple {
	// idx := int(c.hasher.Sum32()) % len(ConfigVar.Plat.Src)
	idx := int(murmur3.Sum32(ipt.IP6)) % len(ConfigVar.Plat.Src)
	ipt.IP4 = CopyIP(ConfigVar.Plat.Src[idx])
	ipt.Port4 = ipt.Port6
	pp := c.Table46[binary.BigEndian.Uint32(ipt.IP4)]
	pp.GetAndSet(ipt)
	return ipt
}

func (c *Controller) GetIP(ipt *NATuple) *NATuple {
	// return c.Table46[binary.BigEndian.Uint32(ip4t.IP)].Get(ip4t.Port)
	// v, _ := c.Table46.Load(binary.BigEndian.Uint32(ipt.IP4))
	// log.Printf("ip4t.IP == %s", ip4t.IP)
	// if ok == false {
	// 	return nil
	// }
	// pp := v.(*PortPool)
	pp := c.Table46[binary.BigEndian.Uint32(ipt.IP4)]
	return pp.Get(ipt)
}

// func HashIP(srcIP net.IP) net.IP {
// 	pool := ConfigVar.Plat.Src
// 	ip := net.IPv4(0, 0, 0, 0).To4()
// 	for i := 0; i < len(srcIP); i += 4 {
// 		ip[0] ^= srcIP[i+0]
// 		ip[1] ^= srcIP[i+1]
// 		ip[2] ^= srcIP[i+2]
// 		ip[3] ^= srcIP[i+3]
// 	}
// 	prefix, _ := pool.Mask.Size()
// 	i := 0
// 	for prefix > 8 {
// 		ip[i] = pool.IP[i]
// 		i++
// 		prefix -= 8
// 	}
// 	if prefix > 0 {
// 		ip[i] &= byte(0xff) >> uint(prefix)
// 		ip[i] |= pool.IP[i] & (byte(0xff) << uint(8-prefix))
// 	}
// 	return ip
// }

func StartRadvd() error {
	if ConfigVar.Spec.Radvd != nil && ConfigVar.Spec.Radvd.Enable {
		srv, err := radvd.NewServer()
		if err != nil {
			return err
		}
		prefixes := make([]net.IPNet, len(ConfigVar.Spec.Radvd.Prefixes))
		for i, prefix := range ConfigVar.Spec.Radvd.Prefixes {
			_, ipnet, err := net.ParseCIDR(prefix)
			if err != nil {
				return err
			}
			prefixes[i] = *ipnet
		}
		srv.SetPrefixes(prefixes)
		conn, err := net.ListenIP("ip6:ipv6-icmp", &net.IPAddr{net.IPv6unspecified, ""})
		if err != nil {
			return err
		}
		err = srv.SetRdnss(ConfigVar.Spec.Radvd.Rdnss)
		if err != nil {
			return err
		}
		go func() {
			if err := srv.Serve(ConfigVar.Spec.Radvd.Interface, conn); err != nil {
				log.Printf("Failed to start radvd: %s", err)
			}
		}()
	}
	return nil
}

func StartClat() error {
	if ConfigVar.Spec.Clat != nil && ConfigVar.Spec.Clat.Enable {
		clatConfig := &ClatConfig{}
		_, clatSrcNet, err := net.ParseCIDR(ConfigVar.Spec.Clat.Src)
		if err != nil {
			log.Printf("Failed to parse ClatSrcIP: %s", err.Error())
			return err
		}
		clatConfig.Src = clatSrcNet
		_, clatDstNet, err := net.ParseCIDR(ConfigVar.Spec.Clat.Dst)
		if err != nil {
			log.Printf("Failed to parse ClatDstIP: %s", err.Error())
			return err
		}
		clatConfig.Dst = clatDstNet
		ConfigVar.Clat = clatConfig
	}
	return nil
}

func StartPlat() error {
	if ConfigVar.Spec.Plat != nil && ConfigVar.Spec.Plat.Enable {
		platConfig := &PlatConfig{}
		platConfig.Src = make([]net.IP, 0)
		platConfig.SrcIdx = make(map[uint32]int)
		for _, poolStr := range ConfigVar.Spec.Plat.Src {
			sp := strings.Split(poolStr, "-")
			if len(sp) == 2 {
				startIP := binary.BigEndian.Uint32(net.ParseIP(sp[0]).To4())
				endIP := binary.BigEndian.Uint32(net.ParseIP(sp[1]).To4())
				for j := startIP; j <= endIP; j++ {
					ip := make([]byte, 4)
					binary.BigEndian.PutUint32(ip, j)
					platConfig.Src = append(platConfig.Src, net.IP(ip))
					platConfig.SrcIdx[j] = len(platConfig.Src) - 1
				}
			} else {
				//TODO
				return fmt.Errorf("failed to parse plat src %s", poolStr)
			}
		}
		// _, platSrcNet, err := net.ParseCIDR(ConfigVar.Spec.Plat.Src)
		// if err != nil {
		// 	log.Printf("Failed to parse PlatSrcIP: %s", err.Error())
		// 	return err
		// }
		// platConfig.Src = platSrcNet
		_, platDstNet, err := net.ParseCIDR(ConfigVar.Spec.Plat.Dst)
		if err != nil {
			log.Printf("Failed to parse PlatDstIP: %s", err.Error())
			return err
		}
		platConfig.Dst = platDstNet
		ConfigVar.Plat = platConfig
		Ctrl = &Controller{}
		err = Ctrl.Init()
		if err != nil {
			log.Printf("Failed to init Controller: %s", err.Error())
			return err
		}
	}
	return nil
}

func StartDNS() error {
	if ConfigVar.Spec.DNS != nil && ConfigVar.Spec.DNS.Enable {
		dserver, err := dns.NewServer(ConfigVar.Spec.DNS.Forwarders, ConfigVar.Spec.DNS.Prefix)
		if err != nil {
			// log.Printf(err.Error())
			return err
		}
		err = dserver.ListenAndServe("[::]:53")
		if err != nil {
			// log.Printf(err.Error())
			return err
		}
	}
	return nil
}

func StartAPI() error {
	server := &WebInfo{}
	err := server.Init()
	if err != nil {
		return err
	}
	portStr := os.Getenv("APIPORT")
	if portStr == "" {
		portStr = "9090"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("failed to parse APIPORT %s: %s", portStr, err.Error())
	}
	go server.Serve("0.0.0.0", port)
	return nil
}
