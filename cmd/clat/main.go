package main

import (
	"log"
	"net/http"
	"xlat"
	"xlat/clat"

	_ "net/http/pprof"
)

func HandlePacket(data []byte) {
	// log.Printf("new packet %+v", inpkt)
	pkt := xlat.NewPacket(data)
	// pkt.Parse()
	err := pkt.LazyParse()
	if err != nil {
		log.Printf("lazyparse failed %s", err.Error())
		return
	}
	if pkt.Layers[0].Type == xlat.LayerTypeIPv6 {
		// layer := pkt.Layers[0].Parse(pkt).(*layers.IPv6)
		dstIP := pkt.Layers[0].GetDst(pkt)
		if !xlat.ConfigVar.Clat.Src.Contains(dstIP) {
			return
		}
		// log.Printf("[in] %s -> %s %s", layer.SrcIP.String(), layer.DstIP.String(), layer.NextLayerType())
		// pkt.Print()
		// log.Print("ip6 to ip4")
		// pkt.LazyLayers()
		npkt, err := clat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// olayer := npkt.Layers[0].ParsedLayer.(*layers.IPv4)
		// log.Printf("[out] %s -> %s %s", olayer.SrcIP.String(), olayer.DstIP.String(), olayer.NextLayerType())
		// npkt.Parse()
		// npkt.Print()
		// outPkt := &tuntap.Packet{
		// 	Protocol: 0x8000,
		// 	Packet:   npkt.Data,
		// }
		xlat.ConfigVar.Device().Write(npkt.Data)
	} else if pkt.Layers[0].Type == xlat.LayerTypeIPv4 {
		// pkt.Print()
		// pkt.TestICMP4Checksum()
		// log.Print("ip4 to ip6")
		// layer := pkt.Layers[0].ParsedLayer.(*layers.IPv4)
		// log.Printf("[in] %s -> %s %s", layer.SrcIP.String(), layer.DstIP.String(), layer.NextLayerType())
		// pkt.LazyLayers()
		npkt, err := clat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// olayer := npkt.Layers[0].ParsedLayer.(*layers.IPv6)
		// log.Printf("[out] %s -> %s %s", olayer.SrcIP.String(), olayer.DstIP.String(), olayer.NextLayerType())
		// npkt.Parse()
		// npkt.Print()
		// outPkt := &tuntap.Packet{
		// 	Protocol: 0x86dd,
		// 	Packet:   npkt.Data,
		// }
		xlat.ConfigVar.Device().Write(npkt.Data)
	}
}

func main() {
	log.Printf("lalala")
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	_, err := xlat.LoadConfig("../config.json")
	if err != nil {
		log.Printf("failed to load config: %s", err.Error())
		return
	}
	device := xlat.ConfigVar.Device()
	if device == nil {
		log.Printf("failed to init device")
		return
	}
	for true {
		packet := make([]byte, xlat.ConfigVar.Spec.MTU+100)
		// inpkt, err := device.ReadPacket()
		n, err := xlat.ConfigVar.Device().Read(packet)
		// clatCtrl.Device.WritePacket()
		if err != nil {
			log.Printf("%s", err.Error())
			break
		}
		go HandlePacket(packet[:n])

	}

}
