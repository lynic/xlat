package xlat

import (
	"encoding/binary"
	"fmt"
	"log"

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
	HeaderTCPLength      = 20
	HeaderUDPLength      = 8
)

type Packet struct {
	// FirstLayer string
	Data   []byte
	Layers []*Layer
	ipcsum uint32
	// Buffer    []byte
	DataStart int
	DataEnd   int
	Stateful  bool
}

func NewPacket(data []byte) *Packet {
	pkt := &Packet{
		Data: data,
	}
	pkt.Layers = make([]*Layer, 0, 7)
	return pkt
}

func NewPacket2(buffer []byte, dataStart, dataLen int) *Packet {
	pkt := &Packet{
		Data: buffer,
		// Buffer:    buffer,
		DataStart: dataStart,
		DataEnd:   dataStart + dataLen,
	}
	// pkt.Data = pkt.Buffer[dataStart : dataStart+dataLen]
	pkt.Layers = make([]*Layer, 0, 7)
	return pkt
}

func (p *Packet) LazyParse() error {
	if len(p.Layers) != 0 {
		p.Layers = make([]*Layer, 0, 7)
	}

	if IsIPv4Layer(p.Data[p.DataStart:p.DataEnd]) {
		layer := &Layer{
			Type:          LayerTypeIPv4,
			DataStart:     p.DataStart,
			DataEnd:       p.DataStart + HeaderIPv4Length,
			NextLayerType: IPv4NextLayer(p.Data[p.DataStart:p.DataEnd]),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	if IsIPv6Layer(p.Data[p.DataStart:p.DataEnd]) {
		layer := &Layer{
			Type:          LayerTypeIPv6,
			DataStart:     p.DataStart,
			DataEnd:       p.DataStart + HeaderIPv6Length,
			NextLayerType: IPv6NextLayer(p.Data[p.DataStart:p.DataEnd]),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	if IsEthLayer(p.Data[p.DataStart:p.DataEnd]) {
		layer := &Layer{
			Type:          LayerTypeEthernet,
			DataStart:     p.DataStart,
			DataEnd:       p.DataStart + HeaderEthernetLength,
			NextLayerType: EthNextLayer(p.Data[p.DataStart:p.DataEnd]),
		}
		p.Layers = append(p.Layers, layer)
		return nil
	}
	return fmt.Errorf("unknown layer")
}

func (p *Packet) LazyLayers() error {
	dataIndex := p.Layers[0].DataEnd
	nextLayer := p.Layers[0].NextLayerType
	// for dataIndex < len(p.Data[p.DataStart:p.DataEnd]) {
	for dataIndex < p.DataEnd {
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
				DataEnd:       dataIndex + HeaderTCPLength,
				NextLayerType: LayerTypePayload,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
			// for debug
			// player := layer.Parse(p).(*layers.TCP)
			// p.Print()
			// log.Printf("%+v", player.Options)
		case LayerTypeUDP:
			layer := &Layer{
				Type:          LayerTypeUDP,
				DataStart:     dataIndex,
				DataEnd:       dataIndex + HeaderUDPLength,
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
				DataEnd:       p.DataEnd,
			}
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			nextLayer = layer.NextLayerType
		}
	}
	return nil
}

func (p *Packet) GetSrcTuple() *NATuple {
	ipt := &NATuple{}
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == LayerTypeIPv4 {
			ipt.IP4 = p.Layers[i].GetSrc(p)
		}
		if p.Layers[i].Type == LayerTypeIPv6 {
			ipt.IP6 = p.Layers[i].GetSrc(p)
		}
		if p.Layers[i].Type == LayerTypeTCP ||
			p.Layers[i].Type == LayerTypeICMPv4 ||
			p.Layers[i].Type == LayerTypeICMPv6 ||
			p.Layers[i].Type == LayerTypeUDP {
			if ipt.IP4 != nil {
				ipt.Port4 = p.Layers[i].GetSrcPort(p)
			} else {
				ipt.Port6 = p.Layers[i].GetSrcPort(p)
			}
		}
	}
	return ipt
}

func (p *Packet) GetDstTuple() *NATuple {
	ipt := &NATuple{}
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == LayerTypeIPv4 {
			ipt.IP4 = p.Layers[i].GetDst(p)
		}
		if p.Layers[i].Type == LayerTypeIPv6 {
			ipt.IP6 = p.Layers[i].GetDst(p)
		}
		if p.Layers[i].Type == LayerTypeTCP ||
			p.Layers[i].Type == LayerTypeICMPv4 ||
			p.Layers[i].Type == LayerTypeICMPv6 ||
			p.Layers[i].Type == LayerTypeUDP {
			if ipt.IP4 != nil {
				ipt.Port4 = p.Layers[i].GetDstPort(p)
			} else {
				ipt.Port6 = p.Layers[i].GetDstPort(p)
			}
		}
	}
	return ipt
}

func (p *Packet) SetSrcPort(port uint16) error {
	for _, layer := range p.Layers {
		if layer.Type == LayerTypeTCP || layer.Type == LayerTypeUDP {
			binary.BigEndian.PutUint16(p.Data[layer.DataStart:layer.DataStart+2], port)
		}
		if layer.Type == LayerTypeICMPv4 || layer.Type == LayerTypeICMPv6 {
			binary.BigEndian.PutUint16(p.Data[layer.DataStart+4:layer.DataStart+6], port)
		}
	}
	return nil
}

func (p *Packet) SetDstPort(port uint16) error {
	for _, layer := range p.Layers {
		if layer.Type == LayerTypeTCP || layer.Type == LayerTypeUDP {
			binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:layer.DataStart+4], port)
		}
		if layer.Type == LayerTypeICMPv4 || layer.Type == LayerTypeICMPv6 {
			binary.BigEndian.PutUint16(p.Data[layer.DataStart+4:layer.DataStart+6], port)
		}
	}
	return nil
}

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

func (p *Packet) Print() {
	if len(p.Layers) == 0 {
		p.LazyParse()
	}
	if len(p.Layers) == 1 {
		p.LazyLayers()
	}
	log.Printf("Packet start %d end %d layers %+v", p.DataStart, p.DataEnd, p.Layers)
	// log.Printf("pkt %+v", p)
	for i := 0; i < len(p.Layers); i++ {
		log.Printf("%+v", p.Layers[i])
	}
	log.Printf("p.Data: %v", p.Data[p.DataStart:p.DataEnd])
	var packet gopacket.Packet
	if p.Layers[0].Type == LayerTypeIPv4 {
		packet = gopacket.NewPacket(p.Data[p.DataStart:p.DataEnd], layers.LayerTypeIPv4, gopacket.Default)
	} else {
		packet = gopacket.NewPacket(p.Data[p.DataStart:p.DataEnd], layers.LayerTypeIPv6, gopacket.Default)
	}

	log.Printf("goPkt %+v", packet)
}

// func (p *Packet) Taint() {
// 	p.Layers = make([]*Layer, 0)
// }

func (p *Packet) GetData(start int) []byte {
	return p.Data[start:p.DataEnd]
}

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
