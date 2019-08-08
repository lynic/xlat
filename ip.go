package xlat

import (
	"encoding/binary"
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
	if err := ipv6.AddressTo16(); err != nil {
		return nil
	}
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
	ipv4Layer := p.GetLayerByType(LayerTypeIPv4).ToIPLayer()
	// ipLayer := ipv4Layer.Parse(p).(*layers.IPv4)
	ipv6Layer := &layers.IPv6{}

	ipv6Layer.SrcIP = ConfigVar.Clat.Src.IP
	srcIP := ipv4Layer.GetSrc(p)
	ipv6Layer.SrcIP[15] = srcIP[3]
	ipv6Layer.SrcIP[14] = srcIP[2]
	ipv6Layer.SrcIP[13] = srcIP[1]
	ipv6Layer.SrcIP[12] = srcIP[0]
	ipv6Layer.DstIP = ConfigVar.Clat.Dst.IP
	dstIP := ipv4Layer.GetDst(p)
	ipv6Layer.DstIP[15] = dstIP[3]
	ipv6Layer.DstIP[14] = dstIP[2]
	ipv6Layer.DstIP[13] = dstIP[1]
	ipv6Layer.DstIP[12] = dstIP[0]
	// convert next protocol
	// if ipv4Layer.Protocol(p) == layers.IPProtocolICMPv4 {
	if ipv4Layer.Protocol(p) == 1 {
		ipv6Layer.NextHeader = layers.IPProtocolICMPv6
	} else {
		ipv6Layer.NextHeader = layers.IPProtocol(ipv4Layer.Protocol(p))
	}
	ipv6Layer.HopLimit = ipv4Layer.TTL(p)
	ipv6Layer.Version = 6
	ipv6Layer.Length = uint16(len(p.Data[ipv4Layer.DataEnd:]))
	ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)

	newData := append(ipv6Layer.Contents, p.Data[ipv4Layer.DataEnd:]...)
	p.Data = newData
	p.ReplaceIPLayer()
	return p, nil
}

func IP6ToIP4(p *Packet) (*Packet, error) {
	layer := p.GetLayerByType(LayerTypeIPv6).ToIP6Layer()
	// ip6Layer := layer.Parse(p).(*layers.IPv6)
	ipLayer := &layers.IPv4{}

	ipLayer.SrcIP = net.ParseIP("1.1.1.1").To4()
	srcIP := layer.GetSrc(p)
	ipLayer.SrcIP[3] = srcIP[15]
	ipLayer.SrcIP[2] = srcIP[14]
	ipLayer.SrcIP[1] = srcIP[13]
	ipLayer.SrcIP[0] = srcIP[12]
	ipLayer.DstIP = net.ParseIP("1.1.1.1").To4()
	dstIP := layer.GetDst(p)
	ipLayer.DstIP[3] = dstIP[15]
	ipLayer.DstIP[2] = dstIP[14]
	ipLayer.DstIP[1] = dstIP[13]
	ipLayer.DstIP[0] = dstIP[12]
	// convert next protocol
	if layers.IPProtocol(layer.NextHeader(p)) == layers.IPProtocolICMPv6 {
		ipLayer.Protocol = layers.IPProtocolICMPv4
	} else {
		ipLayer.Protocol = layers.IPProtocol(layer.NextHeader(p))
	}
	ipLayer.TTL = layer.HopLimit(p)
	ipLayer.Version = 4
	ipLayer.Length = uint16(HeaderIPv4Length + len(p.Data[layer.DataEnd:]))
	// ipv6Layer.Contents = IPv6HeaderToBytes(ipv6Layer)
	ipLayer.Contents = IPv4HeaderToBytes(ipLayer)
	newData := append(ipLayer.Contents, p.Data[layer.DataEnd:]...)
	p.Data = newData
	p.ReplaceIPLayer()
	return p, nil
}
