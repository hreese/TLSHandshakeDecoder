package TLSHandshakeDecoder

import (
	_ "code.google.com/p/gopacket"
	_ "code.google.com/p/gopacket/pcap"
	"encoding/json"
	"io/ioutil"
)

// list of official cipher suites
type CipherSuite struct {
	Index uint
	Value uint16
	Name  string
}

func ReadTLSCipherlist(filename string) (map[uint]CipherSuite, map[uint]CipherSuite) {
	ciphers := make([]CipherSuite, 0)
	// read cipher suite definition from (slightly modified) IANA list
	if CipherListFile, err := ioutil.ReadFile(filename); err != nil {
		panic(err)
	} else {
		json.Unmarshal(CipherListFile, &ciphers)
	}

	// return map indexed by custom index (== position in official IANA list) and value (as set in HelloClient cipher list)
	var CiphersByIndex = make(map[uint]CipherSuite)
	var CiphersByValue = make(map[uint]CipherSuite)
	for _, v := range ciphers {
		CiphersByIndex[v.Index] = v
		CiphersByValue[uint(v.Value)] = v
	}

	return CiphersByIndex, CiphersByValue
}
