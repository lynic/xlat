package main

import (
	"log"
	"xlat"
	"xlat/clat"

	"github.com/lab11/go-tuntap/tuntap"
)

func main() {
	log.Printf("lalala")
	tapdev, err := tuntap.Open("tun0", tuntap.DevTun, false)
	if err != nil {
		log.Printf("%s", err.Error())
		return
	}
	clatCtrl := &clat.Controller{}
	clatCtrl.Device = tapdev
	for true {
		inpkt, err := clatCtrl.Device.ReadPacket()
		// clatCtrl.Device.WritePacket()
		if err != nil {
			log.Printf("%s", err.Error())
			break
		}
		pkt := xlat.NewPacket(inpkt.Packet)
		pkt.Parse()
		pkt.Print()
		// pkt.TestICMP4Checksum()
		log.Print("ip4 to ip6")
		npkt, err := xlat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		npkt.Parse()
		npkt.Print()
		log.Print("test icmpv6checksum")
		npkt.FillICMPv6Checksum()
		npkt.Parse()
		npkt.Print()
		outPkt := &tuntap.Packet{
			Protocol: 0x86dd,
			Packet:   npkt.Data,
		}
		clatCtrl.Device.WritePacket(outPkt)
		// log.Print("recalc checksum")
		// npkt.TestIPv6Checksum()
		// npkt.Print()
		// for i := 0; i < len(pkt.Layers); i++ {
		// 	log.Printf("%+v\n%+v", pkt.Layers[i], pkt.Layers[i].ParsedLayer)
		// }
		// data, err := clatCtrl.IPv4ToIPv6(inpkt.Packet)
		// if err != nil && err.Error() == "not ipv4 packet" {
		// 	clatCtrl.IPv6ToIPv4(inpkt.Packet)
		// }
		// if err != nil {
		// 	log.Printf(err.Error())
		// 	return
		// }
		// outPkt := &tuntap.Packet{
		// 	Protocol: 6,
		// 	Packet:   data,
		// }
		// clatCtrl.Device.WritePacket(outPkt)
	}

}
