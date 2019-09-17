package xlat

func ConvertPacket(p *Packet) (*Packet, error) {
	if len(p.Layers) == 1 {
		p.LazyLayers()
	}
	var err error
	for i := len(p.Layers) - 1; i >= 0; i-- {
		switch p.Layers[i].Type {
		case LayerTypeICMPv4:
			p, err = ICMP4ToICMP6(p)
			if err != nil {
				return nil, err
			}
		case LayerTypeIPv4:
			p, err = IP4ToIP6(p)
			if err != nil {
				return nil, err
			}
		case LayerTypeICMPv6:
			p, err = ICMP6ToICMP4(p)
			if err != nil {
				return nil, err
			}
		case LayerTypeIPv6:
			p, err = IP6ToIP4(p)
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
