package main

import (
	"log"
	"os"
	"xlat"
)

// func HandlePacket(data []byte) {
func HandlePacket(buffer []byte, dataStart, dataLen int) {
	pkt := xlat.NewPacket2(buffer, dataStart, dataLen)
	err := pkt.LazyParse()
	if err != nil {
		log.Printf("lazyparse failed %s", err.Error())
		return
	}
	if pkt.Layers[0].Type == xlat.LayerTypeIPv6 {
		if xlat.ConfigVar.Enabled(xlat.ServiceClat) == false &&
			xlat.ConfigVar.Enabled(xlat.ServicePlat) == false {
			return
		}
		if xlat.ConfigVar.Enabled(xlat.ServiceClat) &&
			xlat.ConfigVar.Clat.Src.Contains(pkt.Layers[0].GetDst(pkt)) {
			pkt.Stateful = false
		} else if xlat.ConfigVar.Enabled(xlat.ServicePlat) {
			// Use Plat ?
			pkt.Stateful = true
		}
		// if xlat.ConfigVar.Clat == nil
		// pkt.Print()
		// log.Printf("Converting packet")
		npkt, err := xlat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// log.Printf("Converted packet")
		// pkt.Print()
		xlat.ConfigVar.Device().Write(npkt.Data[npkt.DataStart:npkt.DataEnd])
		return
	}
	if pkt.Layers[0].Type == xlat.LayerTypeIPv4 {
		if xlat.ConfigVar.Enabled(xlat.ServicePlat) &&
			xlat.ConfigVar.Plat.SrcContains(pkt.Layers[0].GetDst(pkt)) {
			// Use Plat ?
			pkt.Stateful = true
			// return
		} else if xlat.ConfigVar.Enabled(xlat.ServiceClat) == false {
			return
		}
		// pkt.Print()
		// log.Printf("Converting packet")
		npkt, err := xlat.ConvertPacket(pkt)
		if err != nil {
			log.Printf("%v", err)
			return
		}
		// log.Printf("Converted packet")
		// pkt.Print()
		xlat.ConfigVar.Device().Write(npkt.Data[npkt.DataStart:npkt.DataEnd])
		return
	}
}

func main() {
	log.Printf("Starting xlat")
	confPath := os.Getenv("XLATCONF")
	if confPath == "" {
		log.Printf("Please sepcify env XLATCONF")
		return
	}
	_, err := xlat.LoadConfig(confPath)
	if err != nil {
		log.Printf("failed to load config: %s", err.Error())
		return
	}
	// device := xlat.ConfigVar.Device()
	// if device == nil {
	// 	log.Printf("failed to init device")
	// 	return
	// }
	if xlat.ConfigVar.Enabled(xlat.ServiceAPI) {
		log.Printf("Starting %s", xlat.ServiceAPI)
		err := xlat.StartAPI()
		if err != nil {
			log.Printf("Failed to start API: %s", err.Error())
		}
	}
	if xlat.ConfigVar.Enabled(xlat.ServiceClat) {
		log.Printf("Starting %s", xlat.ServiceClat)
		err = xlat.StartClat()
		if err != nil {
			log.Printf("failed to start clat: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Enabled(xlat.ServicePlat) {
		log.Printf("Starting %s", xlat.ServicePlat)
		err = xlat.StartPlat()
		if err != nil {
			log.Printf("failed to start plat: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Enabled(xlat.ServiceRadvd) {
		log.Printf("Starting %s", xlat.ServiceRadvd)
		err = xlat.StartRadvd()
		if err != nil {
			log.Printf("failed to start radvd: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Enabled(xlat.ServiceDns) {
		log.Printf("Starting %s", xlat.ServiceDns)
		err = xlat.StartDNS()
		if err != nil {
			log.Printf("failed to start dns: %s", err.Error())
		}
	}

	// if xlat.ConfigVar.Enabled(xlat.ServiceDHCP6) {
	// 	log.Printf("Starting %s", xlat.ServiceDHCP6)
	// 	err = xlat.StartDHCP6()
	// 	if err != nil {
	// 		log.Printf("failed to start dhcp6: %s", err.Error())
	// 	}
	// }

	reservSize := 20
	blockSize := xlat.ConfigVar.Spec.MTU + reservSize
	packets := make([]byte, blockSize*xlat.ConfigVar.Spec.BufferSize)
	i := 0
	for true {
		// packet := make([]byte, xlat.ConfigVar.Spec.MTU+100)
		// inpkt, err := device.ReadPacket()
		n, err := xlat.ConfigVar.Device().Read(packets[i*blockSize+reservSize:])
		// clatCtrl.Device.WritePacket()
		if err != nil {
			log.Printf("%s", err.Error())
			break
		}
		// go HandlePacket(packets[i*blockSize+reservSize : i*blockSize+n+reservSize])
		go HandlePacket(packets[i*blockSize:(i+1)*blockSize], reservSize, n)
		i++
		if i >= 10000 {
			i = 0
		}

	}

}
