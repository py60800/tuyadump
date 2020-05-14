// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.
// WARN: Code borrowed from "github.com/google/gopacket"
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	//	"time"

	"github.com/google/gopacket"
	//	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers" // pulls in all layers decoders
	//	"encoding/hex"
	"time"
)

var (
	print       = flag.Bool("print", true, "Print out packets, if false only prints out statistics")
	maxcount    = flag.Int("c", -1, "Only grab this many packets, then exit")
	decoder     = flag.String("decoder", "Ethernet", "Name of the decoder to use")
	dump        = flag.Bool("X", false, "If true, dump very verbose info on each packet")
	statsevery  = flag.Int("stats", 1000, "Output statistics every N packets")
	printErrors = flag.Bool("errors", false, "Print out packet dumps of decode errors, useful for checking decoders against live traffic")
	lazy        = flag.Bool("lazy", false, "If true, do lazy decoding")
	defrag      = flag.Bool("defrag", false, "If true, do IPv4 defrag")
)

func typ(t *layers.TCP) string {
	s := "."
	if t.SYN {
		s = s + "SYN."
	}
	if t.FIN {
		s = s + "FIN."
	}
	if t.ACK {
		s = s + "ACK."
	}
	if t.RST {
		s = s + "RST."
	}
	return s
}
func Run(src gopacket.PacketDataSource) {
	if !flag.Parsed() {
		log.Fatalln("Run called without flags.Parse() being called")
	}
	var dec gopacket.Decoder
	var ok bool
	if dec, ok = gopacket.DecodersByLayerName[*decoder]; !ok {
		log.Fatalln("No decoder named", *decoder)
	}
	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = *lazy
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true
	fmt.Fprintln(os.Stderr, "Starting to read packets")
	var initialTime time.Time
	var prevTime time.Time
	firstLoop := true
	for packet := range source.Packets() {
		var ip *layers.IPv4
		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ = ipLayer.(*layers.IPv4)
		}
		currTime := packet.Metadata().Timestamp
		if firstLoop {
			initialTime = currTime
			prevTime = currTime
			firstLoop = false
		}
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			// Get actual TCP data from this layer
			tcp, _ := tcpLayer.(*layers.TCP)
			fmt.Printf("%v[%3.3f/%3.3f] %v:%d => %v:%d [%v] %v bytes\n",
				getPfx(ip.SrcIP.String()),
				currTime.Sub(initialTime).Seconds(), currTime.Sub(prevTime).Seconds(),
				getDevName(ip.SrcIP.String()), tcp.SrcPort, getDevName(ip.DstIP.String()),
				tcp.DstPort, typ(tcp), len(tcp.Payload))
			if len(tcp.Payload) > 0 {
				processBuffer(tcp.Payload, ip.SrcIP.String(), ip.DstIP.String())
			}
		}
		prevTime = currTime
	}
}
