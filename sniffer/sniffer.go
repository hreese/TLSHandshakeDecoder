package main

import (
    "code.google.com/p/gopacket"
    "code.google.com/p/gopacket/pcap"
    "github.com/davecgh/go-spew/spew"
)

const (
    InterfaceName    = "any"
//    FilterExpression = "port 443"
    FilterExpression = "tcp and port 443 and tcp[(((tcp[12:1] & 0xf0) >> 2)):1] = 0x16 and ((tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x01) or (tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x02))"
)

func main () {
    // open device(s) for reading
    if handle, err := pcap.OpenLive(InterfaceName, 1600, true, pcap.BlockForever); err != nil {
        panic(err)
    // set filter
    } else if err := handle.SetBPFFilter(FilterExpression); err != nil {
        panic(err)
    } else {
        // start capture
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        // handle packets
        for packet := range packetSource.Packets() {
            spew.Dump(packet)
        }
    }
}
