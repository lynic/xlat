package xlat

import (
	"encoding/binary"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type IPLayer struct {
	Layer
}

func (l *IPLayer) Version(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart]) >> 4
}

func (l *IPLayer) IHL(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart]) & 0x0F
}

func (l *IPLayer) Protocol(p *Packet) uint8 {
	return p.Data[l.DataStart+9]
}

func (l *IPLayer) TTL(p *Packet) uint8 {
	return p.Data[l.DataStart+8]
}

// ===================================

type IP6Layer struct {
	Layer
}

func (l *IP6Layer) NextHeader(p *Packet) uint8 {
	return p.Data[l.DataStart+6]
}

func (l *IP6Layer) HopLimit(p *Packet) uint8 {
	return p.Data[l.DataStart+7]
}

// ==========================================================

type Layer struct {
	Type          string
	NextLayerType string
	DataStart     int
	DataEnd       int
	ParsedLayer   gopacket.Layer
}

func (l *Layer) Parse(p *Packet) gopacket.Layer {
	if l.ParsedLayer != nil {
		return l.ParsedLayer
	}
	var packet gopacket.Packet
	switch l.Type {
	case LayerTypeEthernet:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeEthernet)
		if packet == nil {
			return nil
		}
		// layer := packet.Layers()[0].(*layers.Ethernet)
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.Ethernet" {
			return nil
		}
		layer := nlayer.(*layers.Ethernet)
		// if layers.EthernetTypeMetadata[ethLayer.EthernetType].Name == "UnknownEthernetType" {
		if layer.NextLayerType() != layers.LayerTypeIPv4 && layer.NextLayerType() != layers.LayerTypeIPv6 {
			// this is not eth layer
			return nil
		}

		// switch layer.NextLayerType() {
		// case layers.LayerTypeIPv4:
		// 	l.NextLayerType = LayerTypeIPv4
		// case layers.LayerTypeIPv6:
		// 	l.NextLayerType = LayerTypeIPv6
		// default:
		// 	l.NextLayerType = LayerTypePayload
		// }
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeIPv4:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeIPv4)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.IPv4" {
			return nil
		}
		layer := nlayer.(*layers.IPv4)
		if layer.Version != 4 {
			return nil
		}
		// switch layer.NextLayerType() {
		// case layers.LayerTypeICMPv4:
		// 	l.NextLayerType = LayerTypeICMPv4
		// case layers.LayerTypeTCP:
		// 	l.NextLayerType = LayerTypeTCP
		// case layers.LayerTypeUDP:
		// 	l.NextLayerType = LayerTypeUDP
		// default:
		// 	l.NextLayerType = LayerTypePayload
		// }
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeIPv6:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeIPv6)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.IPv6" {
			return nil
		}
		layer := nlayer.(*layers.IPv6)
		if layer.Version != 6 {
			return nil
		}
		// switch layer.NextLayerType() {
		// case layers.LayerTypeICMPv4:
		// 	l.NextLayerType = LayerTypeICMPv4
		// case layers.LayerTypeICMPv6:
		// 	l.NextLayerType = LayerTypeICMPv6
		// case layers.LayerTypeTCP:
		// 	l.NextLayerType = LayerTypeTCP
		// case layers.LayerTypeUDP:
		// 	l.NextLayerType = LayerTypeUDP
		// default:
		// 	l.NextLayerType = LayerTypePayload
		// }
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv4:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeICMPv4)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.ICMPv4" {
			return nil
		}
		layer := nlayer.(*layers.ICMPv4)
		// l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv6:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeICMPv6)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.ICMPv6" {
			return nil
		}
		layer := nlayer.(*layers.ICMPv6)
		// l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeTCP:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeTCP)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.TCP" {
			return nil
		}
		layer := nlayer.(*layers.TCP)
		// l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeUDP:
		packet = ParsePacket(p.Data[l.DataStart:p.DataEnd], layers.LayerTypeUDP)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.UDP" {
			return nil
		}
		layer := nlayer.(*layers.UDP)
		// l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		// l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypePayload:
		// l.DataEnd = p.DataEnd
		l.ParsedLayer = nil
	}

	return l.ParsedLayer
}

// Don't modify it
func (l *Layer) GetSrc(p *Packet) []byte {
	if l.Type == LayerTypeIPv4 {
		return p.Data[l.DataStart+12 : l.DataStart+16]
	}
	if l.Type == LayerTypeIPv6 {
		return p.Data[l.DataStart+8 : l.DataStart+24]
	}
	return nil
}

// don't modify it
func (l *Layer) GetDst(p *Packet) []byte {
	if l.Type == LayerTypeIPv4 {
		return p.Data[l.DataStart+16 : l.DataStart+20]
	}
	if l.Type == LayerTypeIPv6 {
		return p.Data[l.DataStart+24 : l.DataStart+40]
	}
	return nil
}

func (l *Layer) GetSrcPort(p *Packet) uint16 {
	if l.Type == LayerTypeICMPv4 || l.Type == LayerTypeICMPv6 {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+4 : l.DataStart+6])
	}
	if l.Type == LayerTypeTCP {
		return binary.BigEndian.Uint16(p.Data[l.DataStart : l.DataStart+2])
	}
	if l.Type == LayerTypeUDP {
		return binary.BigEndian.Uint16(p.Data[l.DataStart : l.DataStart+2])
	}
	return 0
}

func (l *Layer) GetDstPort(p *Packet) uint16 {
	if l.Type == LayerTypeICMPv4 || l.Type == LayerTypeICMPv6 {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+4 : l.DataStart+6])
	}
	if l.Type == LayerTypeTCP {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+2 : l.DataStart+4])
	}
	if l.Type == LayerTypeUDP {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+2 : l.DataStart+4])
	}
	return 0
}

func (l *Layer) CalcChecksum(p *Packet) error {
	switch l.Type {
	// case LayerTypeIPv4:
	case LayerTypeICMPv6:
		ipcsum := p.GetIPChecksum()
		p.Data[l.DataStart+2] = 0
		p.Data[l.DataStart+3] = 0
		csum := ComputeChecksum(p.Data[l.DataStart:p.DataEnd], layers.IPProtocolICMPv6, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+2:], csum)
		return nil
	case LayerTypeICMPv4:
		// clear checksum
		p.Data[l.DataStart+2] = 0
		p.Data[l.DataStart+3] = 0
		csum := CalcChecksum(p.Data[l.DataStart:p.DataEnd], 0)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+2:], csum)
		return nil
	case LayerTypeTCP:
		// clear checksum
		p.Data[l.DataStart+16] = 0
		p.Data[l.DataStart+17] = 0
		ipcsum := p.GetIPChecksum()
		csum := ComputeChecksum(p.Data[l.DataStart:p.DataEnd], layers.IPProtocolTCP, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+16:], csum)
		return nil
	case LayerTypeUDP:
		// clear checksum
		p.Data[l.DataStart+6] = 0
		p.Data[l.DataStart+7] = 0
		ipcsum := p.GetIPChecksum()
		csum := ComputeChecksum(p.Data[l.DataStart:p.DataEnd], layers.IPProtocolUDP, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+6:], csum)
		return nil
	}
	return nil
}

func (l *Layer) ToIPLayer() *IPLayer {
	if l.Type != LayerTypeIPv4 {
		return nil
	}
	iplayer := &IPLayer{}
	iplayer.Type = l.Type
	iplayer.DataStart = l.DataStart
	iplayer.DataEnd = l.DataEnd
	iplayer.NextLayerType = l.NextLayerType
	return iplayer
}

func (l *Layer) ToIP6Layer() *IP6Layer {
	if l.Type != LayerTypeIPv6 {
		return nil
	}
	iplayer := &IP6Layer{}
	iplayer.Type = l.Type
	iplayer.DataStart = l.DataStart
	iplayer.DataEnd = l.DataEnd
	iplayer.NextLayerType = l.NextLayerType
	return iplayer
}

func (l *Layer) ToICMPLayer() *ICMPLayer {
	if l.Type != LayerTypeICMPv4 && l.Type != LayerTypeICMPv6 {
		return nil
	}
	icmplayer := &ICMPLayer{}
	icmplayer.Type = l.Type
	icmplayer.DataStart = l.DataStart
	icmplayer.DataEnd = l.DataEnd
	icmplayer.NextLayerType = l.NextLayerType
	return icmplayer
}

// func (l *Layer) ToTCPLayer() *TCPLayer {
// 	if l.Type != LayerTypeTCP {
// 		return nil
// 	}
// 	icmplayer := &TCPLayer{}
// 	icmplayer.Type = l.Type
// 	icmplayer.DataStart = l.DataStart
// 	icmplayer.DataEnd = l.DataEnd
// 	icmplayer.NextLayerType = l.NextLayerType
// 	return icmplayer
// }
