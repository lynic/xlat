package clat

//Controller xxx
type Controller struct {
	// Device *tuntap.Interface
}

// func (s *Controller) IPv6LayerToBytes(ipv6Layer *layers.IPv6) []byte {
// 	options := gopacket.SerializeOptions{
// 		ComputeChecksums: true,
// 		FixLengths:       true,
// 	}
// 	newBuffer := gopacket.NewSerializeBuffer()
// 	err := gopacket.SerializeLayers(newBuffer, options, ipv6Layer)
// 	// err := gopacket.SerializePacket(newBuffer, options, packet)
// 	if err != nil {
// 		log.Printf("%s", err.Error())
// 		return nil
// 	}
// 	data := newBuffer.Bytes()
// 	// log.Printf("%v", data)
// 	return data
// }

// func (s *Controller) IPv6HeaderToBytes(ipv6 *layers.IPv6) []byte {
// 	pLen := len(ipv6.Payload)
// 	bytes := make([]byte, 40)

// 	bytes[0] = (ipv6.Version << 4) | (ipv6.TrafficClass >> 4)
// 	bytes[1] = (ipv6.TrafficClass << 4) | uint8(ipv6.FlowLabel>>16)
// 	binary.BigEndian.PutUint16(bytes[2:], uint16(ipv6.FlowLabel))
// 	ipv6.Length = uint16(pLen)
// 	binary.BigEndian.PutUint16(bytes[4:], ipv6.Length)
// 	bytes[6] = byte(ipv6.NextHeader)
// 	bytes[7] = byte(ipv6.HopLimit)
// 	if err := ipv6.AddressTo16(); err != nil {
// 		return nil
// 	}
// 	copy(bytes[8:], ipv6.SrcIP)
// 	copy(bytes[24:], ipv6.DstIP)
// 	return bytes
// }

// func (s *Controller) IPv6ToIPv4(data []byte) ([]byte, error) {
// 	ipLayer := xlat.GetIPv6Layer(data)
// 	if ipLayer.Version != 6 {
// 		log.Printf("Not IPv6 packet")
// 		return nil, nil
// 	}
// 	v6packet := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Default)
// 	log.Printf("inPkt %+v", v6packet)
// 	return nil, nil
// }

// func (s *Controller) IPv4ToIPv6(data []byte) ([]byte, error) {
// 	// options := gopacket.SerializeOptions{
// 	// 	ComputeChecksums: true,
// 	// 	FixLengths: true,
// 	// }

// 	ipLayer := xlat.GetIPLayer(data)
// 	if ipLayer.Version != 4 {
// 		log.Printf("Not IPv4 packet")
// 		return nil, fmt.Errorf("not ipv4 packet")
// 	}
// 	if int(ipLayer.Length) != (len(ipLayer.Payload) + len(ipLayer.Contents)) {
// 		log.Printf("invalid length ")
// 		return nil, fmt.Errorf("invalid length")
// 	}
// 	// if int(ipLayer.IHL*4) != len(ipLayer.LayerContents()) {
// 	if 20 != len(ipLayer.LayerContents()) {
// 		log.Printf("invalid header length ")
// 		return nil, fmt.Errorf("invalid header length")
// 	}
// 	// for debug
// 	v4packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
// 	log.Printf("inPkt %+v", v4packet)

// 	log.Printf("iplayer %+v", ipLayer)
// 	log.Printf("src %s", ipLayer.SrcIP.String())
// 	log.Printf("dst %s", ipLayer.DstIP.String())
// 	log.Printf("content len %d", len(ipLayer.LayerContents()))
// 	log.Printf("payload len %d", len(ipLayer.LayerPayload()))
// 	// Construct a new ipv6layer
// 	ipv6Layer := &layers.IPv6{}
// 	// TODO get from config
// 	ipv6Layer.SrcIP = net.ParseIP("2018::")
// 	ipv6Layer.SrcIP[15] = ipLayer.SrcIP[3]
// 	ipv6Layer.SrcIP[14] = ipLayer.SrcIP[2]
// 	ipv6Layer.SrcIP[13] = ipLayer.SrcIP[1]
// 	ipv6Layer.SrcIP[12] = ipLayer.SrcIP[0]
// 	ipv6Layer.DstIP = net.ParseIP("2019::")
// 	ipv6Layer.DstIP[15] = ipLayer.DstIP[3]
// 	ipv6Layer.DstIP[14] = ipLayer.DstIP[2]
// 	ipv6Layer.DstIP[13] = ipLayer.DstIP[1]
// 	ipv6Layer.DstIP[12] = ipLayer.DstIP[0]
// 	// convert next protocol
// 	if ipLayer.Protocol == layers.IPProtocolICMPv4 {
// 		ipv6Layer.NextHeader = layers.IPProtocolICMPv6
// 		ipv6Layer.Payload = xlat.ICMPv4ToICMPv6(ipLayer.Payload)
// 		// log.Printf("%+v", ipv6Layer.Payload)
// 	} else {
// 		ipv6Layer.NextHeader = ipLayer.Protocol
// 		ipv6Layer.Payload = ipLayer.Payload
// 	}
// 	ipv6Layer.HopLimit = ipLayer.TTL
// 	ipv6Layer.Version = 6
// 	// ipv6Layer.Length = uint16(len(ipv6Layer.Payload))
// 	ipv6Layer.Contents = xlat.IPv6HeaderToBytes(ipv6Layer)
// 	// v6buffer := gopacket.NewSerializeBuffer()
// 	// err := ipv6Layer.SerializeTo(v6buffer, options)
// 	// if err != nil {
// 	// 	log.Printf("%s", err.Error())
// 	// 	return nil, nil
// 	// }
// 	// ipv6Layer.SerializeTo
// 	log.Printf("Converted IPv6")
// 	log.Printf("%+v", ipv6Layer)
// 	log.Printf("src %s", ipv6Layer.SrcIP.String())
// 	log.Printf("dst %s", ipv6Layer.DstIP.String())

// 	//outgoing

// 	packetData := make([]byte, len(ipv6Layer.Contents)+len(ipv6Layer.Payload))
// 	log.Printf("packet len: %d", len(packetData))
// 	i := 0
// 	for j := 0; j < len(ipv6Layer.Contents); j++ {
// 		packetData[i] = ipv6Layer.Contents[j]
// 		i++
// 	}
// 	for j := 0; j < len(ipv6Layer.Payload); j++ {
// 		packetData[i] = ipv6Layer.Payload[j]
// 		i++
// 	}
// 	// tcp.SetNetworkLayerForChecksum(ip)
// 	packet := gopacket.NewPacket(packetData, layers.LayerTypeIPv6, gopacket.Default)
// 	log.Printf("newPacket %+v", packet)
// 	// newBuffer := gopacket.NewSerializeBuffer()
// 	// // err := gopacket.SerializeLayers(newBuffer, options, ipv6Layer)
// 	// err := gopacket.SerializePacket(newBuffer, options, packet)
// 	// if err != nil {
// 	// 	log.Printf("faield to serial packet: %s", err.Error())
// 	// 	return nil, fmt.Errorf("faield to serial packet")
// 	// }
// 	// outgoingPacket := newBuffer.Bytes()
// 	log.Printf("outPkt: %v", packetData)
// 	return packetData, nil
// }
