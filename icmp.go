package xlat

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket/layers"
)

func GetICMPLayer(data []byte) *layers.ICMPv4 {
	packet := ParsePacket(data, layers.LayerTypeICMPv4)
	if packet == nil {
		return nil
	}
	return packet.Layers()[0].(*layers.ICMPv4)
}

func ICMPv6HeaderToBytes(i *layers.ICMPv6) []byte {
	// options := gopacket.SerializeOptions{
	// 	ComputeChecksums: true,
	// 	FixLengths:       true,
	// }
	bytes := make([]byte, 4)
	// i.TypeCode.SerializeTo(bytes)
	// log.Printf("Typecode %v", i.TypeCode)
	binary.BigEndian.PutUint16(bytes, uint16(i.TypeCode))
	bytes[2] = 0
	bytes[3] = 0
	// for j := 4; j < 8; j++ {
	// 	bytes[j] = i.Contents[j]
	// }
	return bytes
	// newBuffer := gopacket.NewSerializeBuffer()
	// err := gopacket.SerializeLayers(newBuffer, options, i)
	// if err != nil {
	// 	log.Printf("failed to serial icmp: %s", err.Error())
	// 	return nil
	// }
	// data := newBuffer.Bytes()
	// return append(data, i.Contents[4:]...)
	// return append(data, i.Payload...)
	// return data
}

func ICMPv4ToICMPv6(src []byte) []byte {
	icmpLayer := GetICMPLayer(src)
	log.Printf("icmp %+v", icmpLayer)
	if icmpLayer == nil {
		log.Printf("failed to decode icmp layer")
		return nil
	}
	icmpv6Layer := &layers.ICMPv6{}
	// icmpv6Layer.Checksum = icmpLayer.Checksum
	switch icmpLayer.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)
	case layers.ICMPv4TypeEchoReply:
		icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)
	}
	// icmpv6Layer.Contents = icmpLayer.Contents
	icmpv6Layer.Payload = append(icmpLayer.Contents[4:], icmpLayer.Payload...)
	// icmpv6Layer.Payload = icmpLayer.Payload
	icmpv6Layer.Contents = ICMPv6HeaderToBytes(icmpv6Layer)
	log.Printf("icmpv6 %+v", icmpv6Layer)
	return append(icmpv6Layer.Contents, icmpv6Layer.Payload...)
}

func ICMP4ToICMP6(p *Packet) (*Packet, error) {
	icmpLayer := p.GetLayerByType(LayerTypeICMPv4)
	icmpv6Layer := &layers.ICMPv6{}
	pLayer := icmpLayer.ParsedLayer.(*layers.ICMPv4)
	switch pLayer.TypeCode.Type() {
	case layers.ICMPv4TypeEchoRequest:
		// icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0)
		binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
			binary.BigEndian.Uint16([]byte{layers.ICMPv6TypeEchoRequest, 0}))
	case layers.ICMPv4TypeEchoReply:
		// icmpv6Layer.TypeCode = layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0)
		binary.BigEndian.PutUint16(p.Data[icmpLayer.DataStart:icmpLayer.DataStart+2],
			binary.BigEndian.Uint16([]byte{layers.ICMPv6TypeEchoReply, 0}))
	default:
		return nil, fmt.Errorf("unsupported icmp type")
	}
	// clear checksum, TODO re-calc
	p.Data[icmpLayer.DataStart+2] = 0
	p.Data[icmpLayer.DataStart+3] = 0
	// icmpv6Layer.Payload = append(pLayer.Contents[4:], pLayer.Payload...)
	icmpv6Layer.Contents = ICMPv6HeaderToBytes(icmpv6Layer)
	// newData := p.Data[:icmpLayer.DataStart]
	// newData = append(newData, icmpv6Layer.Contents...)
	// newData = append(newData, p.Data[icmpLayer.DataEnd:]...)
	// newLayer := &Layer{
	// 	Type:          LayerTypeICMPv6,
	// 	NextLayerType: icmpLayer.NextLayerType,
	// 	DataStart:     icmpLayer.DataStart,
	// 	DataEnd:       icmpLayer.DataStart + len(icmpv6Layer.Contents),
	// 	ParsedLayer:   icmpv6Layer,
	// }
	// p.ReplaceLayer(icmpLayer.Type, newLayer, icmpv6Layer.Contents)
	// p.Data = newData
	//TODO lazy parse
	// p.Taint()
	// p.Parse()
	// p.Print()
	return p, nil
}
