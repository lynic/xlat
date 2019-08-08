package main

import (
	"log"
	"xlat"
	"xlat/clat"

	"net/http"
	_ "net/http/pprof"

	"github.com/google/gopacket/layers"
	"github.com/lab11/go-tuntap/tuntap"
)

func HandlePacket(data []byte) {
	// log.Printf("new packet %+v", inpkt)
	pkt := xlat.NewPacket(data)
	pkt.Parse()
	if pkt.Layers[0].Type == xlat.LayerTypeIPv6 {
		layer := pkt.Layers[0].ParsedLayer.(*layers.IPv6)
		if !xlat.ConfigVar.Clat.Src.Contains(layer.DstIP) {
			return
		}
		// log.Printf("[in] %s -> %s %s", layer.SrcIP.String(), layer.DstIP.String(), layer.NextLayerType())
		// pkt.Print()
		// log.Print("ip6 to ip4")
		npkt, err := clat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// olayer := npkt.Layers[0].ParsedLayer.(*layers.IPv4)
		// log.Printf("[out] %s -> %s %s", olayer.SrcIP.String(), olayer.DstIP.String(), olayer.NextLayerType())
		// npkt.Parse()
		// npkt.Print()
		outPkt := &tuntap.Packet{
			Protocol: 0x8000,
			Packet:   npkt.Data,
		}
		xlat.ConfigVar.Device().WritePacket(outPkt)
	} else if pkt.Layers[0].Type == xlat.LayerTypeIPv4 {
		// pkt.Print()
		// pkt.TestICMP4Checksum()
		// log.Print("ip4 to ip6")
		// layer := pkt.Layers[0].ParsedLayer.(*layers.IPv4)
		// log.Printf("[in] %s -> %s %s", layer.SrcIP.String(), layer.DstIP.String(), layer.NextLayerType())
		npkt, err := clat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// olayer := npkt.Layers[0].ParsedLayer.(*layers.IPv6)
		// log.Printf("[out] %s -> %s %s", olayer.SrcIP.String(), olayer.DstIP.String(), olayer.NextLayerType())
		// npkt.Parse()
		// npkt.Print()
		outPkt := &tuntap.Packet{
			Protocol: 0x86dd,
			Packet:   npkt.Data,
		}
		xlat.ConfigVar.Device().WritePacket(outPkt)
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
	// tapdev, err := tuntap.Open("tun0", tuntap.DevTun, false)
	// if err != nil {
	// 	log.Printf("%s", err.Error())
	// 	return
	// }
	// clatCtrl := &clat.Controller{}
	// clatCtrl.Device = tapdev
	for true {
		inpkt, err := device.ReadPacket()
		// clatCtrl.Device.WritePacket()
		if err != nil {
			log.Printf("%s", err.Error())
			break
		}
		go HandlePacket(inpkt.Packet)
		// log.Printf("new packet %+v", inpkt)
		// pkt := xlat.NewPacket(inpkt.Packet)
		// pkt.Parse()
		// if pkt.Layers[0].Type == xlat.LayerTypeIPv6 {
		// 	layer := pkt.Layers[0].ParsedLayer.(*layers.IPv6)
		// 	if !xlat.ConfigVar.Clat.Src.Contains(layer.DstIP) {
		// 		continue
		// 	}
		// 	pkt.Print()
		// 	log.Print("ip6 to ip4")
		// 	npkt, err := clat.ConvertPacket(pkt)
		// 	if err != nil {
		// 		log.Printf("%v", err)
		// 		return
		// 	}
		// 	npkt.Parse()
		// 	npkt.Print()
		// 	// log.Print("test icmpv6checksum")
		// 	// npkt.FillICMPv6Checksum()
		// 	// npkt.Parse()
		// 	// npkt.Print()
		// 	outPkt := &tuntap.Packet{
		// 		Protocol: 0x8000,
		// 		Packet:   npkt.Data,
		// 	}
		// 	device.WritePacket(outPkt)
		// } else if pkt.Layers[0].Type == xlat.LayerTypeIPv4 {
		// 	pkt.Print()
		// 	// pkt.TestICMP4Checksum()
		// 	log.Print("ip4 to ip6")
		// 	npkt, err := clat.ConvertPacket(pkt)
		// 	if err != nil {
		// 		log.Printf("%v", err)
		// 		return
		// 	}
		// 	npkt.Parse()
		// 	npkt.Print()
		// 	// log.Print("test icmpv6checksum")
		// 	// npkt.FillICMPv6Checksum()
		// 	// npkt.Parse()
		// 	// npkt.Print()
		// 	outPkt := &tuntap.Packet{
		// 		Protocol: 0x86dd,
		// 		Packet:   npkt.Data,
		// 	}
		// 	device.WritePacket(outPkt)
		// }
	}

}
