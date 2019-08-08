package main

import (
	"log"
	"xlat"
	"xlat/clat"

	"github.com/google/gopacket/layers"
	"github.com/lab11/go-tuntap/tuntap"
)

func main() {
	log.Printf("lalala")
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
		log.Printf("new packet %+v", inpkt)
		pkt := xlat.NewPacket(inpkt.Packet)
		pkt.Parse()
		if pkt.Layers[0].Type == xlat.LayerTypeIPv6 {
			layer := pkt.Layers[0].ParsedLayer.(*layers.IPv6)
			if !xlat.ConfigVar.Clat.Src.Contains(layer.DstIP) {
				continue
			}
			pkt.Print()
			log.Print("ip6 to ip4")
			npkt, err := clat.ConvertPacket(pkt)
			if err != nil {
				log.Printf("%v", err)
				return
			}
			npkt.Parse()
			npkt.Print()
			// log.Print("test icmpv6checksum")
			// npkt.FillICMPv6Checksum()
			// npkt.Parse()
			// npkt.Print()
			outPkt := &tuntap.Packet{
				Protocol: 0x8000,
				Packet:   npkt.Data,
			}
			device.WritePacket(outPkt)
		} else if pkt.Layers[0].Type == xlat.LayerTypeIPv4 {
			pkt.Print()
			// pkt.TestICMP4Checksum()
			log.Print("ip4 to ip6")
			npkt, err := clat.ConvertPacket(pkt)
			if err != nil {
				log.Printf("%v", err)
				return
			}
			npkt.Parse()
			npkt.Print()
			// log.Print("test icmpv6checksum")
			// npkt.FillICMPv6Checksum()
			// npkt.Parse()
			// npkt.Print()
			outPkt := &tuntap.Packet{
				Protocol: 0x86dd,
				Packet:   npkt.Data,
			}
			device.WritePacket(outPkt)
		}
	}

}
