package xlat

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

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
	case LayerTypeIPv4:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeIPv4)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.IPv4)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeIPv6:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeIPv6)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.IPv6)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv4:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeICMPv4)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.ICMPv4)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeICMPv6:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeICMPv6)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.ICMPv6)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeTCP:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeTCP)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.TCP)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypeUDP:
		packet = ParsePacket(p.Data[l.DataStart:], layers.LayerTypeUDP)
		if packet == nil {
			return nil
		}
		layer := packet.Layers()[0].(*layers.UDP)
		if layer == nil {
			return nil
		}
		l.ParsedLayer = layer
		l.DataEnd = l.DataStart + len(layer.Contents)
	case LayerTypePayload:
		l.DataEnd = len(p.Data)
		l.ParsedLayer = nil
	}

	return l.ParsedLayer
}

func (p *Packet) ParseLayer(index int) error {
	return nil
}

// func (p *Packet) Parsed() bool {
// 	return len(p.Layers) != 0
// }

func (p *Packet) Parse() error {
	dataIndex := 0
	// layerIndex := 0
	nextLayer := LayerTypeEthernet
	p.Layers = make([]*Layer, 0)
	// packet := ParsePacket(p.Data, layers.LayerTypeEthernet)
	for {
		switch nextLayer {
		case LayerTypeEthernet:
			if len(p.Data[dataIndex:]) < HeaderEthernetLength {
				return fmt.Errorf("invalid packet length for ip layer")
			}
			layer := &Layer{
				Type:      LayerTypeEthernet,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				// return fmt.Errorf("failed to parse %s", layer.Type)
				nextLayer = LayerTypeIPv4
				continue
			}
			// if layerIndex == 0 {
			// 	packet = ParsePacket(p.Data, layers.LayerTypeEthernet)
			// if packet == nil {
			// 	return fmt.Errorf("failed to parse packet")
			// }
			// }

			ethLayer := player.(*layers.Ethernet)
			// log.Printf("ethlayer %+v", ethLayer)
			// if layers.EthernetTypeMetadata[ethLayer.EthernetType].Name == "UnknownEthernetType" {
			if ethLayer.NextLayerType() != layers.LayerTypeIPv4 && ethLayer.NextLayerType() != layers.LayerTypeIPv6 {
				// this is not eth layer
				nextLayer = LayerTypeIPv4
				continue
			}

			switch ethLayer.NextLayerType() {
			case layers.LayerTypeIPv4:
				nextLayer = LayerTypeIPv4
			case layers.LayerTypeIPv6:
				nextLayer = LayerTypeIPv6
			default:
				nextLayer = LayerTypePayload
			}
			layer.NextLayerType = nextLayer
			// layer.DataEnd = dataIndex + len(ethLayer.Contents)
			// layer.ParsedLayer = ethLayer
			// layer := &Layer{
			// 	Type:          LayerTypeEthernet,
			// 	NextLayerType: nextLayer,
			// 	DataStart:     dataIndex,
			// 	DataEnd:       dataIndex + len(ethLayer.Contents),
			// 	ParsedLayer:   ethLayer,
			// }
			p.Layers = append(p.Layers, layer)

			dataIndex = layer.DataEnd
			// layerIndex++
			continue
		case LayerTypeIPv4:
			if len(p.Data[dataIndex:]) < HeaderIPv4Length {
				return fmt.Errorf("invalid packet length for ip layer")
			}
			// if layerIndex == 0 {
			// 	packet = ParsePacket(p.Data, layers.LayerTypeIPv4)
			// 	if packet == nil {
			// 		return fmt.Errorf("failed to parse packet")
			// 	}
			// }
			layer := &Layer{
				Type:      LayerTypeIPv4,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				// return fmt.Errorf("failed to parse %s", layer.Type)
				nextLayer = LayerTypeIPv6
				continue
			}

			ipLayer := player.(*layers.IPv4)
			if ipLayer.Version != 4 {
				nextLayer = LayerTypeIPv6
				continue
			}
			switch ipLayer.NextLayerType() {
			case layers.LayerTypeICMPv4:
				nextLayer = LayerTypeICMPv4
			case layers.LayerTypeTCP:
				nextLayer = LayerTypeTCP
			case layers.LayerTypeUDP:
				nextLayer = LayerTypeUDP
			default:
				nextLayer = LayerTypePayload
			}
			layer.NextLayerType = nextLayer
			// layer := &Layer{
			// 	Type:          LayerTypeIPv4,
			// 	NextLayerType: nextLayer,
			// 	DataStart:     dataIndex,
			// 	DataEnd:       dataIndex + len(ipLayer.Contents),
			// 	ParsedLayer:   ipLayer,
			// }
			p.Layers = append(p.Layers, layer)

			dataIndex = layer.DataEnd
			// layerIndex++
			continue
		case LayerTypeIPv6:
			if len(p.Data[dataIndex:]) < HeaderIPv6Length {
				return fmt.Errorf("invalid packet length for ip6 layer")
			}
			// if layerIndex == 0 {
			// 	packet = ParsePacket(p.Data, layers.LayerTypeIPv6)
			// 	if packet == nil {
			// 		return fmt.Errorf("failed to parse packet")
			// 	}
			// }
			layer := &Layer{
				Type:      LayerTypeIPv6,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				return fmt.Errorf("failed to parse %s", layer.Type)
			}

			ip6Layer := player.(*layers.IPv6)
			if ip6Layer.Version != 6 {
				return fmt.Errorf("packet is not eth/ip/ip6")
			}
			switch ip6Layer.NextLayerType() {
			case layers.LayerTypeICMPv4:
				nextLayer = LayerTypeICMPv4
			case layers.LayerTypeICMPv6:
				nextLayer = LayerTypeICMPv6
			case layers.LayerTypeTCP:
				nextLayer = LayerTypeTCP
			case layers.LayerTypeUDP:
				nextLayer = LayerTypeUDP
			default:
				nextLayer = LayerTypePayload
			}
			layer.NextLayerType = nextLayer
			// layer := &Layer{
			// 	Type:          LayerTypeIPv6,
			// 	NextLayerType: nextLayer,
			// 	DataStart:     dataIndex,
			// 	DataEnd:       dataIndex + len(ip6Layer.Contents),
			// 	ParsedLayer:   ip6Layer,
			// }

			p.Layers = append(p.Layers, layer)

			dataIndex = layer.DataEnd
			// layerIndex++
			continue
		case LayerTypeICMPv4:
			layer := &Layer{
				Type:      LayerTypeICMPv4,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				return fmt.Errorf("failed to parse %s", layer.Type)
			}

			// icmpLayer := player.(*layers.ICMPv4)
			nextLayer = LayerTypePayload
			layer.NextLayerType = nextLayer
			// layer := &Layer{
			// 	Type:          LayerTypeICMPv4,
			// 	NextLayerType: nextLayer,
			// 	DataStart:     dataIndex,
			// 	DataEnd:       dataIndex + len(icmpLayer.Contents),
			// 	ParsedLayer:   icmpLayer,
			// }
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			// layerIndex++
			continue
		case LayerTypeICMPv6:
			layer := &Layer{
				Type:      LayerTypeICMPv6,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				return fmt.Errorf("failed to parse %s", layer.Type)
			}

			// icmp6Layer := player.(*layers.ICMPv6)
			nextLayer = LayerTypePayload
			layer.NextLayerType = nextLayer
			// layer := &Layer{
			// 	Type:          LayerTypeICMPv6,
			// 	NextLayerType: nextLayer,
			// 	DataStart:     dataIndex,
			// 	DataEnd:       dataIndex + len(icmp6Layer.Contents),
			// 	ParsedLayer:   icmp6Layer,
			// }
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
			// layerIndex++
			continue
		case LayerTypeTCP:
			layer := &Layer{
				Type:      LayerTypeTCP,
				DataStart: dataIndex,
			}
			player := layer.Parse(p)
			if player == nil {
				return fmt.Errorf("failed to parse %s", layer.Type)
			}
			nextLayer = LayerTypePayload
			layer.NextLayerType = nextLayer
			p.Layers = append(p.Layers, layer)
			dataIndex = layer.DataEnd
		case LayerTypePayload:
			layer := &Layer{
				Type:          LayerTypePayload,
				NextLayerType: LayerTypeEnd,
				DataStart:     dataIndex,
				DataEnd:       len(p.Data),
			}
			p.Layers = append(p.Layers, layer)
			return nil
		default:
			return nil
		}
	}
	// return packet.Layers()[0].(*layers.IPv4)
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

func (p *Packet) ReplaceLayer(oldLayerType string, layer *Layer, data []byte) error {
	for i := 0; i < len(p.Layers); i++ {
		if p.Layers[i].Type == oldLayerType {
			oldLayer := p.Layers[i]
			newData := p.Data[:oldLayer.DataStart]
			newData = append(newData, data...)
			newData = append(newData, p.Data[oldLayer.DataEnd:]...)
			p.Data = newData
			p.Layers[i] = layer
			break
		}
	}
	return nil
}

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

func (p *Packet) Taint() {
	p.Layers = make([]*Layer, 0)
}

// func (p *Packet) FillIPChecksum() error {
// 	layer := p.GetLayerByType(LayerTypeIPv4)
// 	if layer == nil {
// 		return fmt.Errorf("no %s layer", LayerTypeIPv4)
// 	}

// 	return nil
// }

func (p *Packet) FillTCPChecksum() error {
	layer := p.GetLayerByType(LayerTypeTCP)
	if layer == nil {
		return fmt.Errorf("no %s layer", LayerTypeTCP)
	}
	// clear checksum
	p.Data[layer.DataStart+16] = 0
	p.Data[layer.DataStart+17] = 0
	var ipcsum uint32
	iplayer := p.GetLayerByType(LayerTypeIPv4)
	if iplayer != nil {
		ip := iplayer.ParsedLayer.(*layers.IPv4)
		ipcsum = IPHeaderChecksum(ip.SrcIP, ip.DstIP)
	} else {
		iplayer = p.GetLayerByType(LayerTypeIPv6)
		ip := iplayer.ParsedLayer.(*layers.IPv6)
		ipcsum = IPHeaderChecksum(ip.SrcIP, ip.DstIP)
	}
	csum := ComputeChecksum(p.Data[layer.DataStart:], layers.IPProtocolTCP, ipcsum)
	binary.BigEndian.PutUint16(p.Data[layer.DataStart+16:], csum)
	return nil
}

func (p *Packet) FillICMPv4Checksum() error {
	layer := p.GetLayerByType(LayerTypeICMPv4)
	if layer == nil {
		return fmt.Errorf("no %s layer", LayerTypeICMPv4)
	}
	// clear checksum
	p.Data[layer.DataStart+2] = 0
	p.Data[layer.DataStart+3] = 0
	csum := CalcChecksum(p.Data[layer.DataStart:], 0)
	binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:layer.DataStart+4], csum)
	return nil
}

func (p *Packet) FillICMPv6Checksum() error {
	layer := p.GetLayerByType(LayerTypeIPv6)
	if layer == nil {
		return fmt.Errorf("no %s layer", LayerTypeIPv6)
	}
	ip := layer.ParsedLayer.(*layers.IPv6)
	ipcsum := IPHeaderChecksum(ip.SrcIP, ip.DstIP)
	// log.Printf("ipcsum %d", ipcsum)
	layer = p.GetLayerByType(LayerTypeICMPv6)
	if layer == nil {
		return fmt.Errorf("no %s layer", LayerTypeICMPv6)
	}
	// icmp := layer.ParsedLayer.(*layers.ICMPv6)
	// clear checksum
	p.Data[layer.DataStart+2] = 0
	p.Data[layer.DataStart+3] = 0
	csum := ComputeChecksum(p.Data[layer.DataStart:], layers.IPProtocolICMPv6, ipcsum)
	binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:layer.DataStart+4], csum)
	return nil
}

func (p *Packet) TestIPv6Checksum() error {
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	firstLayerType := layers.LayerTypeIPv6
	// if p.Layers[0].Type == LayerTypeIPv6 {
	// 	firstLayerType = layers.LayerTypeIPv6
	// }
	packet := gopacket.NewPacket(p.Data, firstLayerType, gopacket.Default)
	ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	icmp := packet.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6)
	icmp.SetNetworkLayerForChecksum(ip)
	newBuffer := gopacket.NewSerializeBuffer()
	err := gopacket.SerializePacket(newBuffer, options, packet)
	if err != nil {
		panic(err)
	}
	outgoingPacket := newBuffer.Bytes()
	p.Data = outgoingPacket
	p.Parse()
	return nil
}

func (p *Packet) TestICMP4Checksum() error {
	layer := p.GetLayerByType(LayerTypeICMPv4)
	if layer == nil {
		return fmt.Errorf("no %s layer", LayerTypeICMPv4)
	}
	// clear checksum
	p.Data[layer.DataStart+2] = 0
	p.Data[layer.DataStart+3] = 0
	csum := CalcChecksum(p.Data[layer.DataStart:], 0)
	log.Printf("icmp4 %d", csum)
	// binary.BigEndian.PutUint16(p.Data[layer.DataStart+2:layer.DataStart+4], csum)
	return nil
}

// func (p *Packet) AddIPv6Layer(layer *layers.IPv6) error {
// 	p.Data = append(layer.Contents, p.Data...)
// 	// redo parse?
// 	return nil
// }

// func (p *Packet) AddIPv4Layer(layer *layers.IPv4) error {
// 	p.Data = append(layer.Contents, p.Data...)
// 	return nil
// }

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

func GetIPLayer(data []byte) *layers.IPv4 {
	packet := ParsePacket(data, layers.LayerTypeIPv4)
	if packet == nil {
		return nil
	}
	return packet.Layers()[0].(*layers.IPv4)
}

func GetIPv6Layer(data []byte) *layers.IPv6 {
	packet := ParsePacket(data, layers.LayerTypeIPv6)
	if packet == nil {
		return nil
	}
	return packet.Layers()[0].(*layers.IPv6)
}

func SendUDP(msg []byte, addr string) error {
	//fmt.Printf("Sending UDP packet to %s\n", addr)
	conn, err := net.Dial("udp", addr)
	if err != nil {
		fmt.Printf("Failed to dial remove addr: %v\n", addr)
		return err
	}
	conn.Write(msg)
	conn.Close()
	return nil
}

// func AddVxlanHeader(buf []byte, vni uint32) []byte {
// 	newbuf := make([]byte, len(buf)+8)
// 	copy(newbuf[8:], buf[:])
// 	// Set validIDFlag
// 	newbuf[0] = newbuf[0] | 0x08
// 	// Set vni
// 	vnibuf := make([]byte, 4)
// 	binary.BigEndian.PutUint32(vnibuf, vni)
// 	copy(newbuf[4:7], vnibuf[1:4])
// 	return newbuf
// }

// func IsMultiCast(mac net.HardwareAddr) bool {
// 	multicast_list := []string{
// 		"ff:ff:ff:ff:ff:ff",
// 		"33:33:00:00:00:02",
// 		"33:33:00:00:00:01",
// 		"33:33:00:00:00:16",
// 		"33:33:00:00:00:fb",
// 		"01:00:5e:00:00:16",
// 		"01:00:5e:00:00:fb",
// 	}
// 	dest := mac.String()
// 	for _, v := range multicast_list {
// 		if dest == v {
// 			return true
// 		}
// 	}
// 	return false
// }

// func ReadVxlanHeader(data []byte) (*VxlanHeader, error) {
// 	const vxlanLength = 8
// 	if len(data) < vxlanLength {
// 		return nil, errors.New("not enough length data to build vxlanheader.")
// 	}
// 	if data[0]^0x08 != 0 {
// 		return nil, errors.New("it's not a valid vxlan header")
// 	}
// 	vx := &VxlanHeader{}
// 	// VNI is a 24bit number, Uint32 requires 32 bits
// 	var buf [4]byte
// 	copy(buf[1:], data[4:7])
// 	// RFC 7348 https://tools.ietf.org/html/rfc7348
// 	vx.ValidIDFlag = data[0]&0x08 > 0        // 'I' bit per RFC7348
// 	vx.VNI = binary.BigEndian.Uint32(buf[:]) // VXLAN Network Identifier per RFC7348
// 	// Group Based Policy https://tools.ietf.org/html/draft-smith-vxlan-group-policy-00
// 	vx.GBPExtension = data[0]&0x80 > 0                       // 'G' bit per the group policy draft
// 	vx.GBPDontLearn = data[1]&0x40 > 0                       // 'D' bit - the egress VTEP MUST NOT learn the source address of the encapsulated frame.
// 	vx.GBPApplied = data[1]&0x80 > 0                         // 'A' bit - indicates that the group policy has already been applied to this packet.
// 	vx.GBPGroupPolicyID = binary.BigEndian.Uint16(data[2:4]) // Policy ID as per the group policy draft

// 	// Layer information
// 	vx.Contents = data[:vxlanLength]
// 	vx.Payload = data[vxlanLength:]
// 	return vx, nil
// }

// func ReadEthernetHeader(data []byte) (*EthernetHeader, error) {
// 	const ethernetLength = 14
// 	if len(data) < ethernetLength {
// 		return nil, errors.New("not enough length data to build EthernetHeader.")
// 	}
// 	eth := &EthernetHeader{}
// 	eth.DstMAC = net.HardwareAddr(data[0:6])
// 	eth.SrcMAC = net.HardwareAddr(data[6:12])
// 	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(data[12:14]))

// 	eth.Contents = data[:ethernetLength]
// 	eth.Payload = data[ethernetLength:]
// 	return eth, nil
// }

// func ReadIPv4Header(data []byte) (*IPv4Header, error) {
// 	const ipLength = 20
// 	if len(data) < ipLength {
// 		return nil, errors.New("not enough length data to build IPv4Header.")
// 	}
// 	ip := &IPv4Header{}
// 	flagsfrags := binary.BigEndian.Uint16(data[6:8])

// 	ip.Version = uint8(data[0]) >> 4
// 	ip.IHL = uint8(data[0]) & 0x0F
// 	ip.TOS = data[1]
// 	ip.Length = binary.BigEndian.Uint16(data[2:4])
// 	ip.Id = binary.BigEndian.Uint16(data[4:6])
// 	ip.Flags = IPv4Flag(flagsfrags >> 13)
// 	ip.FragOffset = flagsfrags & 0x1FFF
// 	ip.TTL = data[8]
// 	ip.Protocol = IPProtocol(data[9])
// 	ip.Checksum = binary.BigEndian.Uint16(data[10:12])
// 	ip.SrcIP = data[12:16]
// 	ip.DstIP = data[16:20]
// 	ip.Options = ip.Options[:0]
// 	if ip.Length == 0 {
// 		// If using TSO(TCP Segmentation Offload), length is zero.
// 		// The actual packet length is the length of data.
// 		ip.Length = uint16(len(data))
// 	}
// 	if ip.Length < 20 {
// 		return nil, fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip.Length)
// 	} else if ip.IHL < 5 {
// 		return nil, fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip.IHL)
// 	} else if int(ip.IHL*4) > int(ip.Length) {
// 		return nil, fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip.IHL, ip.Length)
// 	}
// 	ip.Contents = data[:ip.IHL*4]
// 	ip.Payload = data[ip.IHL*4:]
// 	// From here on, data contains the header options.
// 	// Pull out IP options
// 	for (ip.IHL*4 - 20) > 0 {
// 		ndata := make([]byte, ip.IHL*4-20)
// 		copy(ndata[:], data[20:ip.IHL*4])
// 		if ip.Options == nil {
// 			// Pre-allocate to avoid growing the slice too much.
// 			ip.Options = make([]IPv4Option, 0, 4)
// 		}
// 		opt := IPv4Option{OptionType: data[0]}
// 		switch opt.OptionType {
// 		case 0: // End of options
// 			opt.OptionLength = 1
// 			ip.Options = append(ip.Options, opt)
// 			ip.Padding = data[1:]
// 			break
// 		case 1: // 1 byte padding
// 			opt.OptionLength = 1
// 		default:
// 			opt.OptionLength = data[1]
// 			opt.OptionData = data[2:opt.OptionLength]
// 		}
// 		if len(data) >= int(opt.OptionLength) {
// 			data = data[opt.OptionLength:]
// 		} else {
// 			return nil, fmt.Errorf("IP option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
// 		}
// 		ip.Options = append(ip.Options, opt)
// 	}
// 	return ip, nil
// }

// func ReadArpHeader(data []byte) (*ARPHeader, error) {
// 	const arplength = 28
// 	arp := &ARPHeader{}
// 	if len(data) < arplength {
// 		return nil, errors.New("not enough length data to build ARPHeader.")
// 	}
// 	arp.AddrType = LinkType(binary.BigEndian.Uint16(data[0:2]))
// 	arp.Protocol = EthernetType(binary.BigEndian.Uint16(data[2:4]))
// 	arp.HwAddressSize = data[4]
// 	arp.ProtAddressSize = data[5]
// 	arp.Operation = binary.BigEndian.Uint16(data[6:8])
// 	arp.SrcMAC = net.HardwareAddr(data[8 : 8+arp.HwAddressSize])
// 	arp.SrcIP = net.IP(data[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize])
// 	arp.DstMAC = net.HardwareAddr(data[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize])
// 	arp.DstIP = net.IP(data[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize])

// 	arpLength := 8 + 2*arp.HwAddressSize + 2*arp.ProtAddressSize
// 	arp.Contents = data[:arpLength]
// 	arp.Payload = data[arpLength:]
// 	return arp, nil
// }
