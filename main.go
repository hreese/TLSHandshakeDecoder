package main

import (
    "code.google.com/p/gopacket"
    "code.google.com/p/gopacket/pcap"
//    "fmt"
    "github.com/davecgh/go-spew/spew"
    "encoding/json"
    "io/ioutil"
//    "io"
)

type CipherSuite struct {
    Index uint
    Value uint16
    Name string
}

func ReadTLSCipherlist(filename string) map[uint]CipherSuite {
    ciphers := make([]CipherSuite, 0)
    // read cipher suite definition from (slightly modified) IANA list
    if CipherListFile, err := ioutil.ReadFile(filename); err != nil {
        panic(err)
    } else {
        json.Unmarshal(CipherListFile, &ciphers)
    }

    // return map indexed by custom index var (== position in official IANA list)
    var CiphersByIndex = make(map[uint]CipherSuite)
    for _, v := range(ciphers) {
        CiphersByIndex[v.Index] = v
    }

    return CiphersByIndex
}

func main() {
    //CiphersByIndex := ReadTLSCipherlist("iana_tls-params_min.json")

    if handle, err := pcap.OpenOffline("tls_onlyHello_web4.pcap"); err != nil {
        panic(err)
    } else {
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        for packet := range packetSource.Packets() {
            //spew.Dump(packet.ApplicationLayer().Payload())
            spew.Dump(packet.IPLayer())
        }
    }
}
