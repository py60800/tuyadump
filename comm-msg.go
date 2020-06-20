// Copyright 2019 py60800.
// Use of this source code is governed by Apache-2 licence
// license that can be found in the LICENSE file.

package main

import (
   "bytes"
//   "encoding/hex"
   "encoding/json"
   "fmt"
   "io/ioutil"
   "log"
)

type devConfig struct {
   IP      string
   Name    string
   Key     string
   Version string
}
type tconfig struct {
   MasterIP string
   Devices  []devConfig
}

var config tconfig
var devMap map[string]*devConfig

func min(a, b int) int {
   if a < b {
      return a
   }
   return b
}
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
      if len(d.Version) == 0 {
         config.Devices[i].Version = Version_3_1
      }
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
func checkVersion(version string, b []byte) bool {
   if len(b) < len(version) {
      return false
   }
   for i, vb := range version {
      if b[i] != byte(vb) {
         return false
      }
   }
   return true
}
func processPayload31(b []byte, cmd int, dev *devConfig) {
   DDump("Payload:", b)
   var i int
   // Skip leading 0
   for i = 0; i < len(b) && b[i] == byte(0); i++ { }
   b = b[i:]
   if len(b) == 0 {
      fmt.Printf("\tMsg[%2d] Empty msg\n", cmd)
      return
   } 
   if b[0] == byte('{') {
      //  Message supposed to be in clear text
      fmt.Printf("\tMsg[%2d] Clear text : %v\n", cmd, string(b))
   } else {
      if len(b) < len(dev.Version) + 16 + 16 {
           // to short
           fmt.Printf("\tMsg[%2d] ???? \n%v", cmd, SDump(b))
      }else{
         // Try to decrypt
         if bytes.Compare([]byte(dev.Version),b[:len(dev.Version)]) != 0{
           fmt.Printf("\tMsg[%2d] ???? \n%v", cmd, SDump(b))
         } else {
         data, err := aesDecrypt31(b[len(dev.Version)+16:], []byte(dev.Key)) // ignore signature
         if err == nil {
           fmt.Printf("\tMsg[%2d] <V=%v> : %v\n", cmd, dev.Version, string(data))
         }else{
           fmt.Printf("\tMsg[%2d] Decryption error : %v\n%v", cmd, err, data)
         }
         }
       }
   }
}
func processPayload33(b []byte, cmd int, dev *devConfig) {
   DDump(fmt.Sprintf("Payload:(%v)", cmd), b)
   // try to guess message structure
   if len(b) < 4 {
      Dump("Short msg:", b)
      return
   }
   rc := uiRd(b)
   iv := bytes.Index(b[:min(len(b), 8)], []byte(dev.Version))
   rcTxt := ""
   iData := 0
   if (rc & 0xFFFFFF00) == 0 {
      rcTxt = fmt.Sprintf("Rc=%04X ", rc)
      iData = iData + 4
   }
   extraTxt := ""
   if iv >= 0 {
      lv := len(dev.Version)
      extraTxt = fmt.Sprintf("<V=%v:[%02X/%02X/%02X]> ", dev.Version,
         uiRd(b[iv+lv:]), uiRd(b[iv+lv+4:]), uiRd(b[iv+lv+8:]))
      iData = iv + lv + 3*4
   }
   data, err := aesDecrypt33(b[iData:], []byte(dev.Key))
   if err == nil {
      fmt.Printf("\tMsg[%2d] %v%v: %v\n", cmd, rcTxt, extraTxt, string(data))
   } else {
      Dump(fmt.Sprintf("Decrypt error(%v)", err), b)
   }

}
func processBuffer(m []byte, IpSrc string, IpDst string) {
   IP := IpSrc
   if IpSrc == config.MasterIP {
      IP = IpDst
   }
   dev, ok := devMap[IP]
   if !ok {
      Dump(fmt.Sprintf("Unkown Device [%v]", IP), m)
      return
   }
   DDump(fmt.Sprintf("Buffer: from %v to %v (%v)", IpSrc, IpDst, dev.Version), m)
   for {
      if len(m) == 0 {
         fmt.Println("\tEmpty packet")
      }
      if len(m) < (16 + 8) {
         Dump("Partial packet (garbage)?", m)
         break
      }
      hdr := uiRd(m)
      if hdr == uint(0x55aa) && len(m) >= 16+8 {
         cmd := int(uiRd(m[8:]))
         sz := int(uiRd(m[12:]))
         if len(m) < sz+16 {
            Dump(fmt.Sprintf("Incomplete packet<%v/%v>", sz, len(m)), m)
            break
         }
         lgSlice := 16 + sz - 8
         if dev.Version == Version_3_1 {
            processPayload31(m[16:lgSlice], cmd, dev)
         } else {
            processPayload33(m[16:lgSlice], cmd, dev)
         }
         lgSlice = lgSlice + 8 // Discard signature and sync mark
         m = m[lgSlice:]
         if len(m) > 0 {
            fmt.Println("----+++----")
         } else {
            break
         }
      } else {
         Dump("Corrupted packet ?", m)
         break
      }
   }
}
