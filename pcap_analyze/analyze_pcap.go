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
	CiphersByIndex, CiphersByValue := TLSHandshakeDecoder.ReadTLSCipherlist("iana_tls-params_min.json")
    _, _ = CiphersByIndex, CiphersByValue

	if handle, err := pcap.OpenOffline("test.pcap"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			//spew.Dump(packet.ApplicationLayer().Payload())
            payload := packet.ApplicationLayer().Payload()
            var p TLSHandshakeDecoder.TLSRecordLayer
            err = TLSHandshakeDecoder.DecodeRecord(&p, payload); if err != nil {
                panic(err)
            } else {
                fmt.Printf("%#v\n", payload)
                fmt.Printf("%#v\n", p)
            }
            return
		}
	}
}
