package xlat

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/google/gopacket/layers"
)

func IPv6HeaderToBytes(ipv6 *layers.IPv6) []byte {
	// pLen := len(ipv6.Payload)
	bytes := make([]byte, 40)

	bytes[0] = (ipv6.Version << 4) | (ipv6.TrafficClass >> 4)
	bytes[1] = (ipv6.TrafficClass << 4) | uint8(ipv6.FlowLabel>>16)
	binary.BigEndian.PutUint16(bytes[2:], uint16(ipv6.FlowLabel))
	// ipv6.Length = uint16(pLen)
	binary.BigEndian.PutUint16(bytes[4:], ipv6.Length)
	bytes[6] = byte(ipv6.NextHeader)
	bytes[7] = byte(ipv6.HopLimit)
	if err := ipv6.AddressTo16(); err != nil {
		return nil
	}
	copy(bytes[8:], ipv6.SrcIP)
	copy(bytes[24:], ipv6.DstIP)
	return bytes
}

func IPv4HeaderToBytes(ip *layers.IPv4) []byte {
	// optionLength := ip.getIPv4OptionSize()
	bytes := make([]byte, 20)
	// bytes, err := b.PrependBytes(20 + int(optionLength))
	// if err != nil {
	// 	return err
	// }
	// if opts.FixLengths {
	ip.IHL = 5
	// ip.Length = uint16(20)
	// }
	bytes[0] = (ip.Version << 4) | ip.IHL
	bytes[1] = ip.TOS
	binary.BigEndian.PutUint16(bytes[2:], ip.Length)
	binary.BigEndian.PutUint16(bytes[4:], ip.Id)
	var ff uint16
	ff |= uint16(ip.Flags) << 13
	ff |= ip.FragOffset
	binary.BigEndian.PutUint16(bytes[6:], ff)
	bytes[8] = ip.TTL
	bytes[9] = byte(ip.Protocol)
	// if err := ip.AddressTo4(); err != nil {
	// 	return err
	// }
	copy(bytes[12:16], ip.SrcIP)
	copy(bytes[16:20], ip.DstIP)

	// curLocation := 20
	// // Now, we will encode the options
	// for _, opt := range ip.Options {
	// 	switch opt.OptionType {
	// 	case 0:
	// 		// this is the end of option lists
	// 		bytes[curLocation] = 0
	// 		curLocation++
	// 	case 1:
	// 		// this is the padding
	// 		bytes[curLocation] = 1
	// 		curLocation++
	// 	default:
	// 		bytes[curLocation] = opt.OptionType
	// 		bytes[curLocation+1] = opt.OptionLength

	// 		// sanity checking to protect us from buffer overrun
	// 		if len(opt.OptionData) > int(opt.OptionLength-2) {
	// 			return errors.New("option length is smaller than length of option data")
	// 		}
	// 		copy(bytes[curLocation+2:curLocation+int(opt.OptionLength)], opt.OptionData)
	// 		curLocation += int(opt.OptionLength)
	// 	}
	// }

	// if opts.ComputeChecksums {
	ip.Checksum = IPChecksum(bytes)
	// }
	binary.BigEndian.PutUint16(bytes[10:], ip.Checksum)
	return bytes
}

func IP4ToIP6(p *Packet) (*Packet, error) {
	ipv4Layer := p.GetLayerByType(LayerTypeIPv4)
	ipLayer := ipv4Layer.ParsedLayer.(*layers.IPv4)
	ipv6Layer := &layers.IPv6{}

	ipv6Layer.SrcIP = ConfigVar.Clat.Src.IP
	ipv6Layer.SrcIP[15] = ipLayer.SrcIP[3]
	ipv6Layer.SrcIP[14] = ipLayer.SrcIP[2]
	ipv6Layer.SrcIP[13] = ipLayer.SrcIP[1]
	ipv6Layer.SrcIP[12] = ipLayer.SrcIP[0]
	ipv6Layer.DstIP = ConfigVar.Clat.Dst.IP
	ipv6Layer.DstIP[15] = ipLayer.DstIP[3]
	ipv6Layer.DstIP[14] = ipLayer.DstIP[2]
	ipv6Layer.DstIP[13] = ipLayer.DstIP[1]
	ipv6Layer.DstIP[12] = ipLayer.DstIP[0]
	// convert next protocol
	if ipLayer.Protocol == layers.IPProtocolICMPv4 {
		ipv6Layer.NextHeader = layers.IPProtocolICMPv6
	} else {
		ipv6Layer.NextHeader = ipLayer.Protocol
	}
	ipv6Layer.HopLimit = ipLayer.TTL
	ipv6Layer.Version = 6
	ipv6Layer.Length = uint16(len(p.Data[ipv4Layer.DataEnd:]))
	ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)

	newData := append(ipv6Layer.Contents, p.Data[ipv4Layer.DataEnd:]...)
	p.Data = newData
	// newLayer := &Layer{
	// 	Type:      LayerTypeIPv6,
	// 	DataStart: ipv4Layer.DataStart,
	// }

	return p, nil
}

func IP6ToIP4(p *Packet) (*Packet, error) {
	layer := p.GetLayerByType(LayerTypeIPv6)
	ip6Layer := layer.ParsedLayer.(*layers.IPv6)
	log.Printf("ip6 %+v", ip6Layer)
	ipLayer := &layers.IPv4{}

	ipLayer.SrcIP = net.ParseIP("1.1.1.1").To4()
	ipLayer.SrcIP[3] = ip6Layer.SrcIP[15]
	ipLayer.SrcIP[2] = ip6Layer.SrcIP[14]
	ipLayer.SrcIP[1] = ip6Layer.SrcIP[13]
	ipLayer.SrcIP[0] = ip6Layer.SrcIP[12]
	ipLayer.DstIP = net.ParseIP("1.1.1.1").To4()
	ipLayer.DstIP[3] = ip6Layer.DstIP[15]
	ipLayer.DstIP[2] = ip6Layer.DstIP[14]
	ipLayer.DstIP[1] = ip6Layer.DstIP[13]
	ipLayer.DstIP[0] = ip6Layer.DstIP[12]
	// convert next protocol
	if ip6Layer.NextHeader == layers.IPProtocolICMPv6 {
		ipLayer.Protocol = layers.IPProtocolICMPv4
	} else {
		ipLayer.Protocol = ip6Layer.NextHeader
	}
	ipLayer.TTL = ip6Layer.HopLimit
	ipLayer.Version = 4
	ipLayer.Length = uint16(HeaderIPv4Length + len(p.Data[layer.DataEnd:]))
	// ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)
	ipLayer.Contents = IPv4HeaderToBytes(ipLayer)
	log.Printf("ip4 %+v", ipLayer)
	newData := append(ipLayer.Contents, p.Data[layer.DataEnd:]...)
	p.Data = newData
	return p, nil
}

// func ConvertPacket(p *Packet) (*Packet, error) {
// 	var err error
// 	for i := len(p.Layers) - 1; i >= 0; i-- {
// 		switch p.Layers[i].Type {
// 		case LayerTypeICMPv4:
// 			p, err = ICMP4ToICMP6(p)
// 			if err != nil {
// 				return nil, err
// 			}
// 		case LayerTypeIPv4:
// 			p, err = IP4ToIP6(p)
// 			if err != nil {
// 				return nil, err
// 			}
// 		case LayerTypeICMPv6:
// 			return nil, fmt.Errorf("unsupported packet")
// 		case LayerTypeIPv6:
// 			p, err = IP6ToIP4(p)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	}
// 	// reparse packet
// 	p.Parse()
// 	// p.FillTCPChecksum()
// 	// p.FillUDPChecksum()
// 	p.FillICMPv6Checksum()
// 	// p.FillICMPv4Checksum()
// 	// p.FillIPChecksum()
// 	return p, nil
// }
