package xlat

import (
	"encoding/binary"
	"fmt"

	"github.com/google/gopacket/layers"
)

func ICMPType(data []byte) uint8 {
	return uint8(data[0])
}

func ICMPCode(data []byte) uint8 {
	return uint8(data[1])
}

type ICMPLayer struct {
	Layer
}

func (l *ICMPLayer) GetType(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart+0])
}

func (l *ICMPLayer) GetCode(p *Packet) uint8 {
	return uint8(p.Data[l.DataStart+1])
}

func (l *ICMPLayer) GetId(p *Packet) uint16 {
	return binary.BigEndian.Uint16(p.Data[l.DataStart+4 : l.DataStart+6])
}

func (l *ICMPLayer) GetMTU(p *Packet) uint16 {
	if l.Type == LayerTypeICMPv4 {
		return binary.BigEndian.Uint16(p.Data[l.DataStart+7 : l.DataStart+9])
	}
	if l.Type == LayerTypeICMPv6 {
		mtu := binary.BigEndian.Uint32(p.Data[l.DataStart+4 : l.DataStart+9])
		return uint16(mtu)
	}
	return 0
}

func (l *ICMPLayer) SetMTU(p *Packet, mtu uint16) {
	if l.Type == LayerTypeICMPv4 {
		binary.BigEndian.PutUint16(p.Data[l.DataStart+7:], mtu)
	}
	if l.Type == LayerTypeICMPv6 {
		v := uint32(mtu)
		binary.BigEndian.PutUint32(p.Data[l.DataStart+4:], v)
	}
}

// func ICMPv6HeaderToBytes(i *layers.ICMPv6) []byte {
// 	bytes := make([]byte, 4)
// 	binary.BigEndian.PutUint16(bytes, uint16(i.TypeCode))
// 	// clear checksum
// 	bytes[2] = 0
// 	bytes[3] = 0
// 	return bytes
// }

func ICMP4ToICMP6(p *Packet) (*Packet, error) {
	layerIndex := p.LayerIndex(LayerTypeICMPv4)
	icmpLayer := p.Layers[layerIndex].ToICMPLayer()
	// icmpv6Layer := &layers.ICMPv6{}
	// pLayer := icmpLayer.ParsedLayer.(*layers.ICMPv4)
	// switch pLayer.TypeCode.Type() {
	switch icmpLayer.GetType(p) {
	case layers.ICMPv4TypeEchoRequest:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeEchoRequest, 0})
	case layers.ICMPv4TypeEchoReply:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeEchoReply, 0})
	case layers.ICMPv4TypeDestinationUnreachable:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeDestinationUnreachable})
		switch icmpLayer.GetCode(p) {
		case layers.ICMPv4CodeNet:
			fallthrough
		case layers.ICMPv4CodeHost:
			fallthrough
		case layers.ICMPv4CodeSourceRoutingFailed:
			fallthrough
		case layers.ICMPv4CodeNetUnknown:
			fallthrough
		case layers.ICMPv4CodeHostUnknown:
			fallthrough
		case layers.ICMPv4CodeSourceIsolated:
			fallthrough
		case layers.ICMPv4CodeNetTOS:
			fallthrough
		case layers.ICMPv4CodeHostTOS:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv6CodeNoRouteToDst})
		// case layers.ICMPv4CodeProtocol:
		case layers.ICMPv4CodePort:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv6CodePortUnreachable})
		case layers.ICMPv4CodeNetAdminProhibited:
			fallthrough
		case layers.ICMPv4CodeHostAdminProhibited:
			fallthrough
		case layers.ICMPv4CodeCommAdminProhibited:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv6CodeAdminProhibited})
		case layers.ICMPv4CodeFragmentationNeeded:
			copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypePacketTooBig, layers.ICMPv6CodeNoRouteToDst})
			mtu := icmpLayer.GetMTU(p)
			if mtu > 0 {
				icmpLayer.SetMTU(p, mtu)
			} else {
				v := uint16(ConfigVar.Spec.MTU)
				icmpLayer.SetMTU(p, v)
			}
		default:
			return nil, fmt.Errorf("unknown icmpv4 typecode %v", p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2])
		}
	case layers.ICMPv4TypeTimeExceeded:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeTimeExceeded})
	default:
		return nil, fmt.Errorf("unsupported icmp type %v", p.Data[icmpLayer.DataStart:icmpLayer.DataStart+1])
	}
	p.Data[icmpLayer.DataStart+2] = 0
	p.Data[icmpLayer.DataStart+3] = 0
	p.Layers[layerIndex].Type = LayerTypeICMPv6
	p.Layers[layerIndex-1].NextLayerType = p.Layers[layerIndex].Type
	return p, nil
}

func ICMP6ToICMP4(p *Packet) (*Packet, error) {
	layerIndex := p.LayerIndex(LayerTypeICMPv6)
	icmpLayer := p.Layers[layerIndex].ToICMPLayer()
	// pLayer := icmpLayer.ParsedLayer.(*layers.ICMPv6)
	// switch pLayer.TypeCode.Type() {
	switch icmpLayer.GetType(p) {
	case layers.ICMPv6TypeEchoRequest:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeEchoRequest, 0})
	case layers.ICMPv6TypeEchoReply:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeEchoReply, 0})
	case layers.ICMPv6TypeDestinationUnreachable:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeDestinationUnreachable})
		switch icmpLayer.GetCode(p) {
		case layers.ICMPv6CodeNoRouteToDst:
			fallthrough
		case layers.ICMPv6CodeBeyondScopeOfSrc:
			fallthrough
		case layers.ICMPv6CodeAddressUnreachable:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv4CodeHost})
		case layers.ICMPv6CodePortUnreachable:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv4CodePort})
		case layers.ICMPv6CodeAdminProhibited:
			copy(p.Data[icmpLayer.DataStart+1:], []byte{layers.ICMPv4CodeHostAdminProhibited})
		default:
			return nil, fmt.Errorf("unsupported icmp6 typecode %v", p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2])
		}
	case layers.ICMPv6TypeTimeExceeded:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeTimeExceeded})
	case layers.ICMPv6TypePacketTooBig:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded})
		mtu := icmpLayer.GetMTU(p)
		if mtu > 0 {
			icmpLayer.SetMTU(p, mtu-20)
		} else {
			v := uint16(ConfigVar.Spec.MTU)
			icmpLayer.SetMTU(p, v-20)
		}

	default:
		return nil, fmt.Errorf("unsupported icmp6 type %v", p.Data[icmpLayer.DataStart:icmpLayer.DataStart+1])
	}
	p.Data[icmpLayer.DataStart+2] = 0
	p.Data[icmpLayer.DataStart+3] = 0
	p.Layers[layerIndex].Type = LayerTypeICMPv4
	p.Layers[layerIndex-1].NextLayerType = p.Layers[layerIndex].Type
	return p, nil
}
