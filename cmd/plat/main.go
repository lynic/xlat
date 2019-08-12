package main

import (
	"log"
	"net/http"
	"os"
	"xlat"

	_ "net/http/pprof"
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
		if !xlat.ConfigVar.Clat.Src.Contains(pkt.Layers[0].GetDst(pkt)) && xlat.Ctrl != nil {
			// Use Plat ?
			pkt.Stateful = true
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
	} else if pkt.Layers[0].Type == xlat.LayerTypeIPv4 && xlat.Ctrl != nil {
		if xlat.ConfigVar.Plat.Src.Contains(pkt.Layers[0].GetDst(pkt)) {
			// Use Plat ?
			pkt.Stateful = true
			// return
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
	}
}

func main() {
	log.Printf("Starting xlat")
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
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

	if xlat.ConfigVar.Spec.Clat != nil && xlat.ConfigVar.Spec.Clat.Enable {
		log.Printf("Staring clat")
		err = xlat.StartClat()
		if err != nil {
			log.Printf("failed to start clat: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Spec.Plat != nil && xlat.ConfigVar.Spec.Plat.Enable {
		log.Printf("Starting plat")
		err = xlat.StartPlat()
		if err != nil {
			log.Printf("failed to start clat: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Spec.Radvd != nil && xlat.ConfigVar.Spec.Radvd.Enable {
		log.Printf("Starting radvd")
		err = xlat.StartRadvd()
		if err != nil {
			log.Printf("failed to start clat: %s", err.Error())
		}
	}

	if xlat.ConfigVar.Spec.DNS != nil && xlat.ConfigVar.Spec.DNS.Enable {
		log.Printf("Starting dns")
		go xlat.StartDNS()
	}

	reservSize := 20
	blockSize := xlat.ConfigVar.Spec.MTU + reservSize
	packets := make([]byte, blockSize*xlat.ConfigVar.Spec.PoolSize)
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
