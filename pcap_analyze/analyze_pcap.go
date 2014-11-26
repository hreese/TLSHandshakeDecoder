package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"github.com/hreese/TLSHandshakeDecoder"
	"fmt"
	_ "github.com/davecgh/go-spew/spew"
	_ "io"
)

func main() {
	if handle, err := pcap.OpenOffline("test.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			//spew.Dump(packet.ApplicationLayer().Payload())
            payload := packet.ApplicationLayer().Payload()
            var p TLSHandshakeDecoder.TLSRecordLayer
            // decode record layer
            err = TLSHandshakeDecoder.DecodeRecord(&p, payload); if err != nil {
                panic(err)
            } else {
                // decode handshake
                var ph TLSHandshakeDecoder.TLSHandshake
                err = TLSHandshakeDecoder.TLSDecodeHandshake(&ph, p.fragment); if err != nil {
                    panic(err)
                } else {
                    // decode client hello packet
                    var pch TLSHandshakeDecoder.TLSClientHello
                    TLSHandshakeDecoder.TLSDecodeClientHello(&pch, ph.data); if err != nil {
                        panic(err)
                    } else {
                        fmt.Printf("%#v\n", pch)
                    }
                }
            }
            return
		}
	}
}
