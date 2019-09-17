package xlat

type EtherLayer struct {
	Data []byte
}

func IsEthLayer(data []byte) bool {
	if len(data) < HeaderEthernetLength {
		return false
	}
	if EthNextLayer(data) == LayerTypePayload {
		return false
	}
	return true
}

func EthNextLayer(data []byte) string {
	if data[12] == 0x08 && data[13] == 0x00 {
		return LayerTypeIPv4
	}
	if data[12] == 0x86 && data[13] == 0xDD {
		return LayerTypeIPv6
	}
	return LayerTypePayload
}

func (l *EtherLayer) NextLayerType() string {
	if l.Data[12] == 0x08 && l.Data[13] == 0x00 {
		return LayerTypeIPv4
	}
	if l.Data[12] == 0x86 && l.Data[13] == 0xDD {
		return LayerTypeIPv6
	}
	return LayerTypePayload
}
