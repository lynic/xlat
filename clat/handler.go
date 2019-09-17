package clat

import (
	"xlat"
)

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
