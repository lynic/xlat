package xlat

import (
	"encoding/binary"
	"fmt"
	"log"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

const IPPROTOV4 = 0x0800

const IPPROTOV6 = 0x86dd

// type Packet struct {
// 	// The Ethernet type of the packet. Commonly seen values are
// 	// 0x0800 for IPv4 and 0x86dd for IPv6.
// 	Protocol int
// 	// True if the packet was too large to be read completely.
// 	Truncated bool
// 	// The raw bytes of the Ethernet payload (for DevTun) or the full
// 	// Ethernet frame (for DevTap).
// 	Packet []byte
// }
const (
	LayerTypeEthernet = "eth"
	LayerTypeIPv4     = "ipv4"
	LayerTypeIPv6     = "ipv6"
	LayerTypeICMPv4   = "icmpv4"
	LayerTypeICMPv6   = "icmpv6"
	LayerTypeTCP      = "tcp"
	LayerTypeUDP      = "udp"
	LayerTypePayload  = "payload"
	LayerTypeEnd      = "end"
)

const (
	HeaderEthernetLength = 14
	HeaderIPv4Length     = 20
	HeaderIPv6Length     = 40
	HeaderICMPv4Length   = 8
)

type Layer struct {
	Type          string
	NextLayerType string
	DataStart     int
	DataEnd       int
	ParsedLayer   gopacket.Layer
}

type Packet struct {
	// FirstLayer string
	Data   []byte
	Layers []*Layer
	ipcsum uint32
}

func NewPacket(data []byte) *Packet {
	pkt := &Packet{
		Data: data,
	}
	pkt.Layers = make([]*Layer, 0)
	return pkt
}

func (l *Layer) Parse(p *Packet) gopacket.Layer {
	if l.ParsedLayer != nil {
		return l.ParsedLayer
	}
	var packet gopacket.Packet
	switch l.Type {
	case LayerTypeEthernet:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeIPv4)
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

		switch layer.NextLayerType() {
		case layers.LayerTypeIPv4:
			l.NextLayerType = LayerTypeIPv4
		case layers.LayerTypeIPv6:
			l.NextLayerType = LayerTypeIPv6
		default:
			l.NextLayerType = LayerTypePayload
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeIPv4:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeIPv4)
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
		switch layer.NextLayerType() {
		case layers.LayerTypeICMPv4:
			l.NextLayerType = LayerTypeICMPv4
		case layers.LayerTypeTCP:
			l.NextLayerType = LayerTypeTCP
		case layers.LayerTypeUDP:
			l.NextLayerType = LayerTypeUDP
		default:
			l.NextLayerType = LayerTypePayload
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeIPv6:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeIPv6)
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
		switch layer.NextLayerType() {
		case layers.LayerTypeICMPv4:
			l.NextLayerType = LayerTypeICMPv4
		case layers.LayerTypeICMPv6:
			l.NextLayerType = LayerTypeICMPv6
		case layers.LayerTypeTCP:
			l.NextLayerType = LayerTypeTCP
		case layers.LayerTypeUDP:
			l.NextLayerType = LayerTypeUDP
		default:
			l.NextLayerType = LayerTypePayload
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv4:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeICMPv4)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.ICMPv4" {
			return nil
		}
		layer := nlayer.(*layers.ICMPv4)
		l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv6:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeICMPv6)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.ICMPv6" {
			return nil
		}
		layer := nlayer.(*layers.ICMPv6)
		l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeTCP:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeTCP)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.TCP" {
			return nil
		}
		layer := nlayer.(*layers.TCP)
		l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeUDP:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeUDP)
		if packet == nil {
			return nil
		}
		nlayer := packet.Layers()[0]
		if reflect.TypeOf(nlayer).String() != "*layers.UDP" {
			return nil
		}
		layer := nlayer.(*layers.UDP)
		l.NextLayerType = LayerTypePayload
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypePayload:
		l.DataEnd = len(p.Data)
		l.ParsedLayer = nil
	}

	return l.ParsedLayer
}

func (l *Layer) GetSrc(p *Packet) []byte {
	if l.Type == LayerTypeIPv4 {
		return p.Data[l.DataStart+12 : l.DataStart+16]
	}
	if l.Type == LayerTypeIPv6 {
		return p.Data[l.DataStart+8 : l.DataStart+24]
	}
	return nil
}

func (l *Layer) GetDst(p *Packet) []byte {
	if l.Type == LayerTypeIPv4 {
		return p.Data[l.DataStart+16 : l.DataStart+20]
	}
	if l.Type == LayerTypeIPv6 {
		return p.Data[l.DataStart+24 : l.DataStart+40]
	}
	return nil
}

func (l *Layer) CalcChecksum(p *Packet) error {
	switch l.Type {
	// case LayerTypeIPv4:
	case LayerTypeICMPv6:
		ipcsum := p.GetIPChecksum()
		p.Data[l.DataStart+2] = 0
		p.Data[l.DataStart+3] = 0
		csum := ComputeChecksum(p.Data[l.DataStart:], layers.IPProtocolICMPv6, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+2:], csum)
		return nil
	case LayerTypeICMPv4:
		// clear checksum
		p.Data[l.DataStart+2] = 0
		p.Data[l.DataStart+3] = 0
		csum := CalcChecksum(p.Data[l.DataStart:], 0)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+2:], csum)
		return nil
	case LayerTypeTCP:
		// clear checksum
		p.Data[l.DataStart+16] = 0
		p.Data[l.DataStart+17] = 0
		ipcsum := p.GetIPChecksum()
		csum := ComputeChecksum(p.Data[l.DataStart:], layers.IPProtocolTCP, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+16:], csum)
		return nil
	case LayerTypeUDP:
		// clear checksum
		p.Data[l.DataStart+6] = 0
		p.Data[l.DataStart+7] = 0
		ipcsum := p.GetIPChecksum()
		csum := ComputeChecksum(p.Data[l.DataStart:], layers.IPProtocolUDP, ipcsum)
		binary.BigEndian.PutUint16(p.Data[l.DataStart+6:], csum)
		return nil
	}
	return nil
}

func (p *Packet) LazyParse() error {
	p.Layers = make([]*Layer, 0)
	if IsEthLayer(p.Data) {
		layer := &Layer{
			Type:          LayerTypeEthernet,
			DataStart:     0,
			DataEnd:       HeaderEthernetLength,
			NextLayerType: EthNextLayer(p.Data),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	if IsIPv4Layer(p.Data) {
		layer := &Layer{
			Type:          LayerTypeIPv4,
			DataStart:     0,
			DataEnd:       HeaderIPv4Length,
			NextLayerType: IPv4NextLayer(p.Data),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	if IsIPv6Layer(p.Data) {
		layer := &Layer{
			Type:          LayerTypeIPv6,
			DataStart:     0,
			DataEnd:       HeaderIPv6Length,
			NextLayerType: IPv6NextLayer(p.Data),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	return fmt.Errorf("unknown layer")
}

func (p *Packet) LazyLayers() error {
	dataIndex := p.Layers[0].DataEnd
	nextLayer := p.Layers[0].NextLayerType
	for dataIndex < len(p.Data) {
		switch nextLayer {
		case LayerTypeICMPv4:
			layer := &Layer{
				Type:          LayerTypeICMPv4,
				DataStart:     dataIndex,
				DataEnd:       dataIndex + 8,
				NextLayerType: LayerTypePayload,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		case LayerTypeICMPv6:
			layer := &Layer{
				Type:          LayerTypeICMPv6,
				DataStart:     dataIndex,
				DataEnd:       dataIndex + 8,
				NextLayerType: LayerTypePayload,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		case LayerTypeTCP:
			layer := &Layer{
				Type:          LayerTypeTCP,
				DataStart:     dataIndex,
				DataEnd:       dataIndex + 20,
				NextLayerType: LayerTypePayload,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		case LayerTypeUDP:
			layer := &Layer{
				Type:          LayerTypeUDP,
				DataStart:     dataIndex,
				DataEnd:       dataIndex + 8,
				NextLayerType: LayerTypePayload,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		case LayerTypePayload:
			layer := &Layer{
				Type:          LayerTypePayload,
				NextLayerType: LayerTypeEnd,
				DataStart:     dataIndex,
				DataEnd:       len(p.Data),
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		}
	}
	return nil
}

// func (p *Packet) Parse() error {
// 	dataIndex := 0
// 	// layerIndex := 0
// 	nextLayer := LayerTypeEthernet
// 	p.Layers = make([]*Layer, 0)
// 	// packet := ParsePacket(p.Data, layers.LayerTypeEthernet)
// 	for dataIndex < len(p.Data) {
// 		switch nextLayer {
// 		case LayerTypeEthernet:
// 			if len(p.Data[dataIndex:]) < HeaderEthernetLength {
// 				return fmt.Errorf("invalid packet length for ip layer")
// 			}
// 			layer := &Layer{
// 				Type:      LayerTypeEthernet,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				// return fmt.Errorf("failed to parse %s", layer.Type)
// 				nextLayer = LayerTypeIPv4
// 				continue
// 			}
// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 			// layerIndex++
// 			continue
// 		case LayerTypeIPv4:
// 			if len(p.Data[dataIndex:]) < HeaderIPv4Length {
// 				return fmt.Errorf("invalid packet length for ip layer")
// 			}
// 			layer := &Layer{
// 				Type:      LayerTypeIPv4,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				// return fmt.Errorf("failed to parse %s", layer.Type)
// 				nextLayer = LayerTypeIPv6
// 				continue
// 			}
// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 			// layerIndex++
// 			continue
// 		case LayerTypeIPv6:
// 			if len(p.Data[dataIndex:]) < HeaderIPv6Length {
// 				return fmt.Errorf("invalid packet length for ip6 layer")
// 			}

// 			layer := &Layer{
// 				Type:      LayerTypeIPv6,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				return fmt.Errorf("failed to parse %s", layer.Type)
// 			}
// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 			// layerIndex++
// 			continue
// 		case LayerTypeICMPv4:
// 			layer := &Layer{
// 				Type:      LayerTypeICMPv4,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				return fmt.Errorf("failed to parse %s", layer.Type)
// 			}

// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 			// layerIndex++
// 			continue
// 		case LayerTypeICMPv6:
// 			layer := &Layer{
// 				Type:      LayerTypeICMPv6,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				return fmt.Errorf("failed to parse %s", layer.Type)
// 			}

// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 			// layerIndex++
// 			continue
// 		case LayerTypeTCP:
// 			layer := &Layer{
// 				Type:      LayerTypeTCP,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				return fmt.Errorf("failed to parse %s", layer.Type)
// 			}
// 			// nextLayer = LayerTypePayload
// 			// layer.NextLayerType = nextLayer
// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 		case LayerTypeUDP:
// 			layer := &Layer{
// 				Type:      LayerTypeUDP,
// 				DataStart: dataIndex,
// 			}
// 			player := layer.Parse(p)
// 			if player == nil {
// 				return fmt.Errorf("failed to parse %s", layer.Type)
// 			}
// 			// nextLayer = LayerTypePayload
// 			// layer.NextLayerType = nextLayer
// 			nextLayer = layer.NextLayerType
// 			p.Layers = append(p.Layers, layer)
// 			dataIndex = layer.DataEnd
// 		case LayerTypePayload:
// 			layer := &Layer{
// 				Type:          LayerTypePayload,
// 				NextLayerType: LayerTypeEnd,
// 				DataStart:     dataIndex,
// 				DataEnd:       len(p.Data),
// 			}
// 			p.Layers = append(p.Layers, layer)
// 			return nil
// 		default:
// 			return nil
// 		}
// 	}
// 	// return packet.Layers()[0].(*layers.IPv4)
// 	return nil
// }

func (p *Packet) GetLayerByType(layerType string) *Layer {
	//TODO check parse
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == layerType {
			return p.Layers[i]
		}
	}
	return nil
}

func (p *Packet) LayerIndex(layerType string) int {
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == layerType {
			return i
		}
	}
	return 0
}

// func (p *Packet) ReplaceLayer(oldLayerType string, layer *Layer, data []byte) error {
// 	for i := 0; i < len(p.Layers); i++ {
// 		if p.Layers[i].Type == oldLayerType {
// 			oldLayer := p.Layers[i]
// 			newData := p.Data[:oldLayer.DataStart]
// 			newData = append(newData, data...)
// 			newData = append(newData, p.Data[oldLayer.DataEnd:]...)
// 			p.Data = newData
// 			p.Layers[i] = layer
// 			break
// 		}
// 	}
// 	return nil
// }

func (p *Packet) ReplaceIPLayer() {
	delta := 0
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == LayerTypeIPv4 {
			layer := p.Layers[i]
			layer.Type = LayerTypeIPv6
			delta = 20
			layer.DataEnd += delta
			continue
		}
		if p.Layers[i].Type == LayerTypeIPv6 {
			layer := p.Layers[i]
			layer.Type = LayerTypeIPv4
			delta = -20
			layer.DataEnd += delta
			continue
		}
		if delta != 0 {
			p.Layers[i].DataStart += delta
			p.Layers[i].DataEnd += delta
		}
	}
}

// func (p *Packet) ReplaceLayerByIndex(layerInd int, layer *Layer) {
// 	layers := p.Layers[:layerInd]
// 	layers = append(layers, layer)
// 	if layerInd+1 != len(p.Layers) {
// 		layers = append(layers, p.Layers[layerInd+1:]...)
// 	}
// }

func (p *Packet) Print() {
	for i := 0; i < len(p.Layers); i++ {
		log.Printf("%+v\n%+v", p.Layers[i], p.Layers[i].ParsedLayer)
	}
	log.Printf("p.Data: %v", p.Data)
	var packet gopacket.Packet
	if p.Layers[0].Type == LayerTypeIPv4 {
		packet = gopacket.NewPacket(p.Data, layers.LayerTypeIPv4, gopacket.Default)
	} else {
		packet = gopacket.NewPacket(p.Data, layers.LayerTypeIPv6, gopacket.Default)
	}

	log.Printf("goPkt %+v", packet)
}

// func (p *Packet) Taint() {
// 	p.Layers = make([]*Layer, 0)
// }

// func (p *Packet) FillTCPChecksum() error {
// 	layer := p.GetLayerByType(LayerTypeTCP)
// 	if layer == nil {
// 		return fmt.Errorf("no %s layer", LayerTypeTCP)
// 	}
// 	// clear checksum
// 	p.Data[layer.DataStart+16] = 0
// 	p.Data[layer.DataStart+17] = 0
// 	ipcsum := p.GetIPChecksum()
// 	csum := ComputeChecksum(p.Data[layer.DataStart:], layers.IPProtocolTCP, ipcsum)
// 	binary.BigEndian.PutUint16(p.Data[layer.DataStart+16:], csum)
// 	return nil
// }

// func (p *Packet) FillUDPChecksum() error {
// 	layer := p.GetLayerByType(LayerTypeUDP)
// 	if layer == nil {
// 		return fmt.Errorf("no %s layer", LayerTypeUDP)
// 	}
// 	// clear checksum
// 	p.Data[layer.DataStart+6] = 0
// 	p.Data[layer.DataStart+7] = 0
// 	ipcsum := p.GetIPChecksum()
// 	csum := ComputeChecksum(p.Data[layer.DataStart:], layers.IPProtocolUDP, ipcsum)
// 	binary.BigEndian.PutUint16(p.Data[layer.DataStart+6:], csum)
// 	return nil
// }

// func (p *Packet) FillICMPv4Checksum() error {
// 	layer := p.GetLayerByType(LayerTypeICMPv4)
// 	if layer == nil {
// 		return fmt.Errorf("no %s layer", LayerTypeICMPv4)
// 	}
// 	// clear checksum
// 	p.Data[layer.DataStart+2] = 0
// 	p.Data[layer.DataStart+3] = 0
// 	csum := CalcChecksum(p.Data[layer.DataStart:], 0)
// 	binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:], csum)
// 	return nil
// }

// func (p *Packet) FillICMPv6Checksum() error {
// 	ipcsum := p.GetIPChecksum()
// 	// log.Printf("ipcsum %d", ipcsum)
// 	layer := p.GetLayerByType(LayerTypeICMPv6)
// 	if layer == nil {
// 		return fmt.Errorf("no %s layer", LayerTypeICMPv6)
// 	}
// 	// icmp := layer.ParsedLayer.(*layers.ICMPv6)
// 	// clear checksum
// 	p.Data[layer.DataStart+2] = 0
// 	p.Data[layer.DataStart+3] = 0
// 	csum := ComputeChecksum(p.Data[layer.DataStart:], layers.IPProtocolICMPv6, ipcsum)
// 	binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:], csum)
// 	return nil
// }

func (p *Packet) GetIPChecksum() uint32 {
	if p.ipcsum != 0 {
		return p.ipcsum
	}
	var ipcsum uint32
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == LayerTypeIPv4 || p.Layers[i].Type == LayerTypeIPv6 {
			ipcsum = IPHeaderChecksum(p.Layers[i].GetSrc(p), p.Layers[i].GetDst(p))
		}
	}
	p.ipcsum = ipcsum
	return ipcsum
}

func ParsePacket(data []byte, decoder gopacket.Decoder) gopacket.Packet {
	options := gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	}
	packet := gopacket.NewPacket(data, decoder, options)
	if packet.Layers()[0].LayerType() != decoder {
		return nil
	}
	return packet
}
