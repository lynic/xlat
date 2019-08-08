package xlat

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"

	"github.com/lab11/go-tuntap/tuntap"
)

type XlatConfig struct {
	// DeviceName string
	device *tuntap.Interface
	Spec   *XlatConfigSpec
	Clat   *ClatConfig
}

type ClatConfig struct {
	Src *net.IPNet
	// SrcPos int
	Dst *net.IPNet
	// DstPos int
}

type XlatConfigSpec struct {
	DeviceName string `json:"device"`
	Clat       *struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	} `json:"clat"`
	Plat *struct {
	} `json:"plat"`
}

// type ClatConfigSpec struct {
// 	Src string `json:"src"`
// 	Dst string `json:"dst"`
// }

// type PlatConfigSpec struct {
// }

var ConfigVar *XlatConfig

func (c *XlatConfig) Device() *tuntap.Interface {
	if c.device != nil {
		return c.device
	}
	dev, err := tuntap.Open(c.Spec.DeviceName, tuntap.DevTun, false)
	if err != nil {
		log.Printf("Failed to load device %s: %s", c.Spec.DeviceName, err.Error())
		return nil
	}
	c.device = dev
	return c.device
}

func LoadConfig(configPath string) (*XlatConfig, error) {
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Printf("Failed to find config: %s", err.Error())
		return nil, err
	}
	configSpec := &XlatConfigSpec{}
	err = json.Unmarshal(data, configSpec)
	if err != nil {
		log.Printf("Failed to load config: %s", err.Error())
		return nil, err
	}
	clatConfig := &ClatConfig{}
	_, clatSrcNet, err := net.ParseCIDR(configSpec.Clat.Src)
	if err != nil {
		log.Printf("Failed to parse ClatSrcIP: %s", err.Error())
		return nil, err
	}
	clatConfig.Src = clatSrcNet
	_, clatDstNet, err := net.ParseCIDR(configSpec.Clat.Dst)
	if err != nil {
		log.Printf("Failed to parse ClatDstIP: %s", err.Error())
		return nil, err
	}
	clatConfig.Dst = clatDstNet
	ConfigVar = &XlatConfig{
		Spec: configSpec,
		Clat: clatConfig,
	}
	return ConfigVar, nil
}

func Addr(ipNet *net.IPNet) string {
	return ipNet.IP.String()
}

func Mask(ipNet *net.IPNet) int {
	pos, _ := ipNet.Mask.Size()
	return pos
}
