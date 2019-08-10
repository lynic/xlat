package xlat

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

func IsIPv4Layer(data []byte) bool {
	if len(data) < HeaderIPv4Length {
		return false
	}
	if data[0]>>4 == 0x4 && int(binary.BigEndian.Uint16(data[2:4])) == len(data) && IPv4NextLayer(data) != LayerTypePayload {
		return true
	}
	return false
}

func IPv4NextLayer(data []byte) string {
	switch data[9] {
	// case layers.IPProtocolICMPv4:
	case 1:
		return LayerTypeICMPv4
	// case layers.IPProtocolTCP:
	case 6:
		return LayerTypeTCP
	// case layers.IPProtocolUDP:
	case 17:
		return LayerTypeUDP
	}
	return LayerTypePayload
}

func IsIPv6Layer(data []byte) bool {
	if len(data) < HeaderIPv6Length {
		return false
	}
	if data[0]>>4 == 0x6 && int(binary.BigEndian.Uint16(data[4:6])) == len(data)-40 && IPv6NextLayer(data) != LayerTypePayload {
		return true
	}
	return false
}

func IPv6NextLayer(data []byte) string {
	switch data[6] {
	// case layers.IPProtocolICMPv6:
	case 58:
		return LayerTypeICMPv6
	// case layers.IPProtocolTCP:
	case 6:
		return LayerTypeTCP
	// case layers.IPProtocolUDP:
	case 17:
		return LayerTypeUDP
	}
	return LayerTypePayload
}

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
	// if err := ipv6.AddressTo16(); err != nil {
	// 	return nil
	// }
	copy(bytes[8:], ipv6.SrcIP)
	copy(bytes[24:], ipv6.DstIP)
	return bytes
}

func IPv4HeaderToBytes(ip *layers.IPv4) []byte {
	bytes := make([]byte, 20)
	ip.IHL = 5
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

	copy(bytes[12:16], ip.SrcIP)
	copy(bytes[16:20], ip.DstIP)
	ip.Checksum = IPChecksum(bytes)
	binary.BigEndian.PutUint16(bytes[10:], ip.Checksum)
	return bytes
}

func IP4ToIP6(p *Packet) (*Packet, error) {
	layerIndex := p.LayerIndex(LayerTypeIPv4)
	ipv4Layer := p.Layers[layerIndex].ToIPLayer()
	// ipLayer := ipv4Layer.Parse(p).(*layers.IPv4)
	ipv6Layer := &layers.IPv6{}

	// ipv6Layer.SrcIP = ConfigVar.Clat.Src.IP
	if p.Stateful {
		ipv6Layer.SrcIP = make(net.IP, net.IPv6len)
		copy(ipv6Layer.SrcIP, ConfigVar.Plat.Dst.IP)
		srcIP := ipv4Layer.GetSrc(p)
		copy(ipv6Layer.SrcIP[12:], srcIP)
	} else {
		ipv6Layer.SrcIP = make(net.IP, net.IPv6len)
		copy(ipv6Layer.SrcIP, ConfigVar.Clat.Src.IP)
		srcIP := ipv4Layer.GetSrc(p)
		copy(ipv6Layer.SrcIP[12:], srcIP)
	}
	// ipv6Layer.SrcIP[15] = srcIP[3]
	// ipv6Layer.SrcIP[14] = srcIP[2]
	// ipv6Layer.SrcIP[13] = srcIP[1]
	// ipv6Layer.SrcIP[12] = srcIP[0]
	// ipv6Layer.DstIP = ConfigVar.Clat.Dst.IP
	if p.Stateful {
		ip4t := p.GetDstTuple()
		// log.Printf("lookup ip4t %+v", ip4t)
		ip6t := Ctrl.GetIP(ip4t)
		// log.Printf("return ip6t %+v", ip6t)
		if ip6t == nil {
			return nil, fmt.Errorf("Failed to find tuple by %s %d", ip4t.IP, ip4t.Port)
		}
		ipv6Layer.DstIP = make(net.IP, net.IPv6len)
		copy(ipv6Layer.DstIP, ip6t.IP)
		// return nil, fmt.Errorf("stateful unsupported")
	} else {
		ipv6Layer.DstIP = make(net.IP, net.IPv6len)
		copy(ipv6Layer.DstIP, ConfigVar.Clat.Dst.IP)
		dstIP := ipv4Layer.GetDst(p)
		copy(ipv6Layer.DstIP[12:], dstIP)
	}

	// ipv6Layer.DstIP[15] = dstIP[3]
	// ipv6Layer.DstIP[14] = dstIP[2]
	// ipv6Layer.DstIP[13] = dstIP[1]
	// ipv6Layer.DstIP[12] = dstIP[0]
	// convert next protocol
	// if ipv4Layer.Protocol(p) == layers.IPProtocolICMPv4 {
	if ipv4Layer.Protocol(p) == 1 {
		ipv6Layer.NextHeader = layers.IPProtocolICMPv6
	} else {
		ipv6Layer.NextHeader = layers.IPProtocol(ipv4Layer.Protocol(p))
	}
	ipv6Layer.HopLimit = ipv4Layer.TTL(p)
	ipv6Layer.Version = 6
	ipv6Layer.Length = uint16(len(p.Data[ipv4Layer.DataEnd:p.DataEnd]))
	ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)
	// newData := make([]byte, len(ipv6Layer.Contents)+len(p.Data[ipv4Layer.DataEnd:]))
	// copy(newData, ipv6Layer.Contents)
	// copy(newData[len(ipv6Layer.Contents):], p.Data[ipv4Layer.DataEnd:])
	// p.Data = newData
	copy(p.Data[ipv4Layer.DataEnd-len(ipv6Layer.Contents):], ipv6Layer.Contents)
	p.Layers[layerIndex].DataStart = ipv4Layer.DataEnd - len(ipv6Layer.Contents)
	p.DataStart = p.Layers[layerIndex].DataStart
	// p.Data = p.Buffer[p.DataStart:p.DataEnd]
	// p.ReplaceIPLayer()
	p.Layers[layerIndex].Type = LayerTypeIPv6
	return p, nil
}

func IP6ToIP4(p *Packet) (*Packet, error) {
	layerIndex := p.LayerIndex(LayerTypeIPv4)
	layer := p.Layers[layerIndex].ToIP6Layer()
	// ip6Layer := layer.Parse(p).(*layers.IPv6)
	ipLayer := &layers.IPv4{}

	// ipLayer.SrcIP = net.ParseIP("1.1.1.1").To4()
	// ipLayer.SrcIP = net.IP(make([]byte, 4))

	if p.Stateful {
		ip6t := p.GetSrcTuple()
		ip4t := Ctrl.AllocIP(ip6t)
		ipLayer.SrcIP = net.IPv4(ip4t.IP[0], ip4t.IP[1], ip4t.IP[2], ip4t.IP[3]).To4()
		// return nil, fmt.Errorf("stateful unsupported")
	} else {
		srcIP := layer.GetSrc(p)
		ipLayer.SrcIP = net.IPv4(srcIP[12], srcIP[13], srcIP[14], srcIP[15]).To4()
	}

	// copy(ipLayer.SrcIP, srcIP[12:16])
	// ipLayer.SrcIP[3] = srcIP[15]
	// ipLayer.SrcIP[2] = srcIP[14]
	// ipLayer.SrcIP[1] = srcIP[13]
	// ipLayer.SrcIP[0] = srcIP[12]
	// ipLayer.DstIP = net.ParseIP("1.1.1.1").To4()
	// ipLayer.SrcIP = net.IP(make([]byte, 4))
	dstIP := layer.GetDst(p)
	ipLayer.DstIP = net.IPv4(dstIP[12], dstIP[13], dstIP[14], dstIP[15]).To4()
	// ipLayer.DstIP[3] = dstIP[15]
	// ipLayer.DstIP[2] = dstIP[14]
	// ipLayer.DstIP[1] = dstIP[13]
	// ipLayer.DstIP[0] = dstIP[12]
	// convert next protocol
	if layers.IPProtocol(layer.NextHeader(p)) == layers.IPProtocolICMPv6 {
		// if layer.NextHeader(p) == 58 {
		ipLayer.Protocol = layers.IPProtocolICMPv4
	} else {
		ipLayer.Protocol = layers.IPProtocol(layer.NextHeader(p))
	}
	ipLayer.TTL = layer.HopLimit(p)
	ipLayer.Version = 4
	ipLayer.Length = uint16(HeaderIPv4Length + len(p.Data[layer.DataEnd:p.DataEnd]))
	// ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)
	ipLayer.Contents = IPv4HeaderToBytes(ipLayer)
	copy(p.Data[layer.DataEnd-len(ipLayer.Contents):], ipLayer.Contents)
	p.Layers[layerIndex].DataStart = layer.DataEnd - len(ipLayer.Contents)
	p.DataStart = p.Layers[layerIndex].DataStart
	p.Layers[layerIndex].Type = LayerTypeIPv4
	// p.Data = p.Data[layer.DataEnd-len(ipLayer.Contents):]
	// p.Data = p.Data[:len(p.Data)-20]
	// p.ReplaceIPLayer()
	return p, nil
}
