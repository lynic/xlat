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
		// icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeEchoRequest, 0})
		// binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
		// 	binary.BigEndian.Uint16([]byte{layers.ICMPv6TypeEchoRequest, 0}))
	case layers.ICMPv4TypeEchoReply:
		// icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv6TypeEchoReply, 0})
		// binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
		// 	binary.BigEndian.Uint16([]byte{layers.ICMPv6TypeEchoReply, 0}))
	default:
		return nil, fmt.Errorf("unsupported icmp type")
	}
	// clear checksum, TODO re-calc
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
		// binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
		// 	binary.BigEndian.Uint16([]byte{layers.ICMPv4TypeEchoRequest, 0}))
	case layers.ICMPv6TypeEchoReply:
		copy(p.Data[icmpLayer.DataStart:], []byte{layers.ICMPv4TypeEchoReply, 0})
		// binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
		// 	binary.BigEndian.Uint16([]byte{layers.ICMPv4TypeEchoReply, 0}))
	default:
		return nil, fmt.Errorf("unsupported icmp type")
	}
	// clear checksum, TODO re-calc
	p.Data[icmpLayer.DataStart+2] = 0
	p.Data[icmpLayer.DataStart+3] = 0
	p.Layers[layerIndex].Type = LayerTypeICMPv4
	p.Layers[layerIndex-1].NextLayerType = p.Layers[layerIndex].Type
	return p, nil
}
