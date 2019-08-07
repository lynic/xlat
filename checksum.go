package xlat

import (
	"net"

	"github.com/google/gopacket/layers"
)

// Calculate the TCP/IP checksum defined in rfc1071.  The passed-in csum is any
// initial checksum data that's already been computed.
func CalcChecksum(data []byte, csum uint32) uint16 {
	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(data) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(data[i]) << 8
		csum += uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		csum += uint32(data[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	return ^uint16(csum)
}

// computeChecksum computes a TCP or UDP checksum.  headerAndPayload is the
// serialized TCP or UDP header plus its payload, with the checksum zero'd
// out. headerProtocol is the IP protocol number of the upper-layer header.
func ComputeChecksum(headerAndPayload []byte, headerProtocol layers.IPProtocol, headerChecksum uint32) uint16 {
	length := uint32(len(headerAndPayload))
	// log.Printf("headerandpayload %v", headerAndPayload)
	csum := headerChecksum
	csum += uint32(headerProtocol)
	csum += length & 0xffff
	csum += length >> 16
	// log.Printf("headerProtocol csum %d", csum)
	return CalcChecksum(headerAndPayload, csum)
}

func IPHeaderChecksum(SrcIP, DstIP net.IP) (csum uint32) {
	if len(SrcIP) == 4 {
		// ip4
		csum += (uint32(SrcIP[0]) + uint32(SrcIP[2])) << 8
		csum += uint32(SrcIP[1]) + uint32(SrcIP[3])
		csum += (uint32(DstIP[0]) + uint32(DstIP[2])) << 8
		csum += uint32(DstIP[1]) + uint32(DstIP[3])
		// return csum
	} else {
		// ip6
		for i := 0; i < 16; i += 2 {
			csum += uint32(SrcIP[i]) << 8
			csum += uint32(SrcIP[i+1])
			csum += uint32(DstIP[i]) << 8
			csum += uint32(DstIP[i+1])
		}
		// return csum
	}
	return csum
}

// input is only IP header
func IPChecksum(bytes []byte) uint16 {
	// Clear checksum bytes
	bytes[10] = 0
	bytes[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(bytes); i += 2 {
		csum += uint32(bytes[i]) << 8
		csum += uint32(bytes[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	return ^uint16(csum)
}
