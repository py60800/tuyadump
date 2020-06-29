// Copyright 2019 py60800.
// Use of this source code is governed by Apache-2 licence
// license that can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
)

type devConfig struct {
	IP      string
	Name    string
	Key     string
	Version *string
}
type tconfig struct {
	MasterIP string
	Devices  []devConfig
}

var config tconfig
var devMap map[string]*devConfig

func parseConfig(tuyaconf string) {
	b, err := ioutil.ReadFile(tuyaconf)
	if err != nil {
		log.Fatal("Cannot read:", tuyaconf)
	}
	if json.Unmarshal(b, &config) != nil {
		log.Fatal("Cannot understand config file", string(b))
	}
	devMap = make(map[string]*devConfig)
	for i, d := range config.Devices {
		devMap[d.IP] = &config.Devices[i]
	}
}
func getDevName(Ip string) string {
	if Ip == config.MasterIP {
		return "Master"
	}
	n, ok := devMap[Ip]
	if ok {
		return n.Name
	}
	return Ip
}
func getPfx(Ip string) string {
	if Ip == config.MasterIP {
		return "--->>>"
	}
	return "<<<---"
}

var (
	Version_3_1 = "3.1"
	Version_3_3 = "3.3"
)

// helpers
func ui2b(v uint, n int) []byte {
	b := make([]byte, n)
	for v > 0 {
		n = n - 1
		b[n] = byte(v & 0xff)
		v = v >> 8
	}
	return b
}

func uiRd(b []byte) uint {
	r := uint(0)
	for i := 0; i < 4; i++ {
		r = r<<8 | (uint(b[i]) & 0xff)
	}
	return r
}

func processPayload(b []byte, cmd int, Key []byte, version string) {
	var i int
	emark := "Clear text"
	for i = 0; i < len(b) && b[i] == byte(0); i++ {
	}
	b = b[i:]
	if len(b) == 0 {
		fmt.Printf("\t[%v]Null packet\n", cmd)
		return
	} // empty
	var data []byte
	if b[0] == byte('{') && version == Version_3_1{
		//  Message in clear text
		data = b
	} else {
		hasVersion := false
		if len(b) > (len(version) + 16) {
			// Check if message starts with version number
			hasVersion = true
			for i, vb := range version {
				hasVersion = hasVersion && b[i] == byte(vb)
			}
		}
		encrypted := true
		if version == Version_3_1 && !hasVersion {
			encrypted = false
		}
		if !encrypted {
			fmt.Println("\tClear text", string(b))
			return
		}
		emark = "Encrypted"
		var err error
		if len(Key) > 0 {
			if version == Version_3_1 {
				// Should this be 12?
				data, err = aesDecrypt(b[len(version)+16:], Key, version) // ignore signature
			} else {
				if hasVersion {
					data, err = aesDecrypt(b[len(version)+12:], Key, version) // ignore signature
				} else {
					data, err = aesDecrypt(b[0:], Key, version)
				}
			}
			if err != nil {
				fmt.Println("\tDecrypt error:", err)
				return
			}
		} else {
			data = []byte(hex.EncodeToString(b))
		}
	}
	fmt.Printf("\t%v->[%v]:%v\n", emark, cmd, string(data))
}
func processBuffer(m []byte, IpSrc string, IpDst string) {
	IP := IpSrc
	if IpSrc == config.MasterIP {
		IP = IpDst
	}
	Key := []byte{}
	version := Version_3_1
	dev, ok := devMap[IP]
	if ok {
		Key = []byte(dev.Key)
		if dev.Version != nil {
			version = *dev.Version
		}
	}

	for {
		if len(m) == 0 {
			fmt.Println("\tEmpty packet")
		}
		if len(m) < (16 + 8) {
			//Dump("Partial packet (garbage)?", m)
			break
		}
		hdr := uiRd(m)
		if hdr == uint(0x55aa) && len(m) >= 16+8 {
			cmd := int(uiRd(m[8:]))
			sz := int(uiRd(m[12:]))
			rc := int(uiRd(m[16:]))
			hasReturnCode := (rc & 0xFFFFFF00) == 0
			if (sz + 16) <= len(m) {
				if hasReturnCode {
					processPayload(m[16+4:16+sz-8], cmd, Key, version)
					m = m[16+sz:]
				} else {
					processPayload(m[16:16+sz-8], cmd, Key, version)
					m = m[16+sz:]
				}
				if len(m) > 0 {
					fmt.Println("----+++----")
				} else {
					break
				}
			} else {
				//Dump(fmt.Sprintf("Incomplete packet<%v/%v>", sz, len(m)), m)
				break
			}
		} else {
			//Dump("Corrupted packet ?", m)
			break
		}
	}
}
