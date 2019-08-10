package xlat

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

type XlatConfig struct {
	// DeviceName string
	device *water.Interface
	Spec   *XlatConfigSpec
	Clat   *ClatConfig
	Plat   *PlatConfig
}

type ClatConfig struct {
	Src *net.IPNet
	Dst *net.IPNet
}

type PlatConfig struct {
	Src *net.IPNet
	Dst *net.IPNet
}

type XlatConfigSpec struct {
	DeviceName string   `json:"device"`
	MTU        int      `json:"mtu"`
	PostCMD    []string `json:"post_cmd"`
	PoolSize   int      `json:"pool_size"`
	Clat       *struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	} `json:"clat"`
	Plat *struct {
		Src string `json:"src"`
		Dst string `json:"dst"`
	} `json:"plat"`
}

// type ClatConfigSpec struct {
// 	Src string `json:"src"`
// 	Dst string `json:"dst"`
// }

// type PlatConfigSpec struct {
// }

var ConfigVar *XlatConfig

// func (c *XlatConfig) Device() *tuntap.Interface {
// 	if c.device != nil {
// 		return c.device
// 	}
// 	dev, err := tuntap.Open(c.Spec.DeviceName, tuntap.DevTun, false)
// 	if err != nil {
// 		log.Printf("Failed to load device %s: %s", c.Spec.DeviceName, err.Error())
// 		return nil
// 	}
// 	c.device = dev
// 	return c.device
// }

func (c *XlatConfig) Device() *water.Interface {
	// if c.device != nil {
	// 	return c.device
	// }
	// deviceConfig := water.Config{
	// 	DeviceType: water.TUN,
	// }
	// deviceConfig.Name = c.Spec.DeviceName
	// deviceConfig.MultiQueue = true
	// dev, err := water.New(deviceConfig)
	// if err != nil {
	// 	log.Printf("Failed to load device %s: %s", c.Spec.DeviceName, err.Error())
	// 	return nil
	// }
	// c.device = dev
	// if c.Spec.PostCMD != nil {
	// 	for _, cmdStr := range c.Spec.PostCMD {
	// 		scmd := strings.Split(cmdStr, " ")
	// 		cmd := exec.Command(scmd[0], scmd[1:]...)
	// 		err := cmd.Run()
	// 		if err != nil {
	// 			log.Printf("Failed to execute '%s': %s", cmdStr, err.Error())
	// 		}
	// 		log.Printf("Executed '%s'", cmdStr)
	// 	}
	// }
	return c.device
}

func (c *XlatConfig) InitDevice() error {
	deviceConfig := water.Config{
		DeviceType: water.TUN,
	}
	deviceConfig.Name = c.Spec.DeviceName
	deviceConfig.MultiQueue = true
	dev, err := water.New(deviceConfig)
	if err != nil {
		// log.Printf("Failed to load device %s: %s", c.Spec.DeviceName, err.Error())
		return err
	}
	c.device = dev
	if c.Spec.PostCMD != nil {
		for _, cmdStr := range c.Spec.PostCMD {
			scmd := strings.Split(cmdStr, " ")
			cmd := exec.Command(scmd[0], scmd[1:]...)
			err := cmd.Run()
			if err != nil {
				log.Printf("Failed to execute '%s': %s", cmdStr, err.Error())
			}
			log.Printf("Executed '%s'", cmdStr)
		}
	}
	return nil
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
	ConfigVar = &XlatConfig{
		Spec: configSpec,
	}
	log.Printf("Initializing device %s", ConfigVar.Spec.DeviceName)
	err = ConfigVar.InitDevice()
	if err != nil {
		log.Printf("Failed to load device %s: %s", ConfigVar.Spec.DeviceName, err.Error())
		return nil, err
	}
	if configSpec.Clat != nil {
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
		ConfigVar.Clat = clatConfig
	}

	if configSpec.Plat != nil {
		platConfig := &PlatConfig{}
		_, platSrcNet, err := net.ParseCIDR(configSpec.Plat.Src)
		if err != nil {
			log.Printf("Failed to parse PlatSrcIP: %s", err.Error())
			return nil, err
		}
		platConfig.Src = platSrcNet
		_, platDstNet, err := net.ParseCIDR(configSpec.Plat.Dst)
		if err != nil {
			log.Printf("Failed to parse PlatDstIP: %s", err.Error())
			return nil, err
		}
		platConfig.Dst = platDstNet
		ConfigVar.Plat = platConfig
		Ctrl = &Controller{}
		err = Ctrl.Init()
		if err != nil {
			log.Printf("Failed to init Controller: %s", err.Error())
			return nil, err
		}
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
