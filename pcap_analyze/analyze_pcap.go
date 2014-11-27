package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/pcap"
	"github.com/hreese/TLSHandshakeDecoder"
	_ "fmt"
	"github.com/davecgh/go-spew/spew"
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
                //spew.Dump(p)
                var ph TLSHandshakeDecoder.TLSHandshake
                err = TLSHandshakeDecoder.TLSDecodeHandshake(&ph, p.Fragment); if err != nil {
                    panic(err)
                } else {
                    // decode client hello packet
                    //spew.Dump(ph)
                    var pch TLSHandshakeDecoder.TLSClientHello
                    err = TLSHandshakeDecoder.TLSDecodeClientHello(&pch, ph.Body); if err != nil {
                        panic(err)
                    } else {
                        //fmt.Printf("%#v\n", pch)
                        spew.Dump(pch)
                    }
                }
            }
            //return
		}
	}
}
