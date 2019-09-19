package dhcp6

import (
	"fmt"
	"log"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv6"
	"github.com/insomniacslk/dhcp/dhcpv6/server6"
	"github.com/insomniacslk/dhcp/iana"
)

const (
	ModifierTypeDNS        = "dns"
	ModifierTypeServerID   = "serverid"
	ModifierTypeSearchList = "domainsearchlist"
)

type DHCP6Server struct {
	// Enable    bool     `json:"enable"`
	// Interface string   `json:"interface"`
	// DNS       []string `json:"dns"`
	iface     *net.Interface
	modifiers map[string]dhcpv6.Modifier
}

func (s *DHCP6Server) Init(ifname string) error {
	if s.modifiers == nil {
		s.modifiers = make(map[string]dhcpv6.Modifier, 0)
		// s.modifiers[dhcpv6.MessageTypeAdvertise] = make([]dhcpv6.Modifier, 0)
		// s.modifiers[dhcpv6.MessageTypeReply] = make([]dhcpv6.Modifier, 0)
		// s.modifiers = make([]dhcpv6.Modifier, 0)
	}
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return err
	}
	s.iface = iface
	duid := dhcpv6.Duid{
		Type:          dhcpv6.DUID_LL,
		HwType:        iana.HWTypeEthernet,
		LinkLayerAddr: s.iface.HardwareAddr,
	}
	s.modifiers[ModifierTypeServerID] = dhcpv6.WithServerID(duid)
	return nil
}

func (s *DHCP6Server) GetModifiers(names []string) []dhcpv6.Modifier {
	ret := make([]dhcpv6.Modifier, 0)
	for _, name := range names {
		if v, ok := s.modifiers[name]; ok {
			ret = append(ret, v)
		}
	}
	return ret
}

func (s *DHCP6Server) SetDNS(dns []string) error {
	// if s.modifiers == nil {
	// 	s.modifiers = make([]dhcpv6.Modifier, 0)
	// }
	if dns != nil && len(dns) != 0 {
		ips := make([]net.IP, len(dns))
		for i, ipStr := range dns {
			ip := net.ParseIP(ipStr)
			if ip == nil {
				return fmt.Errorf("failed to parse dns %s", ipStr)
			}
			ips[i] = ip
		}
		// s.modifiers = append(s.modifiers[], dhcpv6.WithDNS(ips...))
		s.modifiers[ModifierTypeDNS] = dhcpv6.WithDNS(ips...)
	}
	return nil
}

func (s *DHCP6Server) SetDomainSearchList(list []string) error {
	if list != nil && len(list) != 0 {
		s.modifiers[ModifierTypeSearchList] = dhcpv6.WithDomainSearchList(list...)
	}
	return nil
}

func (s *DHCP6Server) handler(conn net.PacketConn, peer net.Addr, m dhcpv6.DHCPv6) {
	// log.Print(m.Summary())
	switch m.Type() {
	// case dhcpv6.MessageTypeSolicit:
	// 	// fallthrough
	// 	msg := m.(*dhcpv6.Message)
	// 	modifiers := s.GetModifiers([]string{ModifierTypeServerID, ModifierTypeDNS, ModifierTypeSearchList})
	// 	resp, err := dhcpv6.NewAdvertiseFromSolicit(msg, modifiers...)
	// 	if err != nil {
	// 		log.Printf("NewAdvertiseFromSolicit failed: %v", err)
	// 		return
	// 	}
	// 	if _, err := conn.WriteTo(resp.ToBytes(), peer); err != nil {
	// 		log.Printf("Cannot reply to client: %v", err)
	// 	}
	// 	log.Print(resp.Summary())
	// 	return
	// case dhcpv6.MessageTypeRequest:
	// 	msg := m.(*dhcpv6.Message)
	// 	modifiers := s.GetModifiers([]string{ModifierTypeDNS, ModifierTypeServerID})
	// 	resp, err := dhcpv6.NewReplyFromMessage(msg, modifiers...)
	// 	if err != nil {
	// 		log.Printf("NewReplyFromMessage failed: %v", err)
	// 		return
	// 	}
	// 	if _, err := conn.WriteTo(resp.ToBytes(), peer); err != nil {
	// 		log.Printf("Cannot reply to client: %v", err)
	// 	}
	// 	log.Print(resp.Summary())
	// 	return
	case dhcpv6.MessageTypeInformationRequest:
		msg := m.(*dhcpv6.Message)
		modifiers := s.GetModifiers([]string{ModifierTypeServerID, ModifierTypeDNS})
		resp, err := dhcpv6.NewReplyFromMessage(msg, modifiers...)
		if err != nil {
			log.Printf("NewReplyFromInformationRequest failed: %v", err)
			return
		}
		if _, err := conn.WriteTo(resp.ToBytes(), peer); err != nil {
			log.Printf("Cannot reply to client: %v", err)
		}
		// log.Print(resp.Summary())
		return
	}
}

func (s *DHCP6Server) ListenAndServe() error {
	laddr := &net.UDPAddr{
		IP:   net.ParseIP("::"),
		Port: dhcpv6.DefaultServerPort,
	}
	server, err := server6.NewServer(s.iface.Name, laddr, s.handler)
	if err != nil {
		return err
	}
	return server.Serve()
}
