package TLSHandshakeDecoder

import (
	_ "bytes"
	"errors"
	"fmt"
    "github.com/davecgh/go-spew/spew"
)

type TLSHandshake struct {
	HandshakeType uint8
	length        uint32
	Body          []byte
}

type TLSClientHello struct {
	version uint16   // 2
	random  [32]byte // 32
	sessionid          []byte   // 1+v
	ciphersuites       []uint16 // 2+v
	compressionMethods []uint8  // 1+v
	// TODO: add support for extensions
}

func __anti_annoy_me_sdfsdfsdfsdf() {
    spew.Dump(23)
}

func TLSDecodeHandshake(p *TLSHandshake, data []byte) error {
	if len(data) < 4 {
		return errors.New("Handshake body too short (<4).")
	}

	p.HandshakeType = uint8(data[0])
	p.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	p.Body = make([]byte, p.length)
	l := copy(p.Body, data[4:4+p.length])
	if l < int(p.length) {
		return fmt.Errorf("Payload to short: copied %d, expected %d.", l, p.length)
	}

	return nil
}

func TLSDecodeClientHello(p *TLSClientHello, data []byte) error {
	if len(data) < 38 {
		return errors.New("Handshake body too short (<4).")
	}

    var offset uint = 0
    // version
	p.version = uint16(data[0])<<8 | uint16(data[1])
    offset += 2
    // random
	copy(p.random[:], data[offset:offset+32])
    offset += 32
    // sessionid
	sessionid_length := uint8(data[34])
    offset += 1
    if sessionid_length > 0 {
        p.sessionid = make([]byte, sessionid_length)
        copy(p.sessionid[:], data[offset:offset+uint(sessionid_length)])
    }
    offset += uint(sessionid_length)
    // ciphersuites
	var num_ciphersuites uint16 = uint16(uint16(data[offset])<<8 | uint16(data[offset+1])) / 2
	offset += 2
	p.ciphersuites = make([]uint16, num_ciphersuites)
	var i uint
	for i = 0; i < uint(num_ciphersuites); i++ {
		p.ciphersuites[i] = uint16(data[offset+2*i])<<8 | uint16(data[offset+2*i+1])
	}
	offset += 2 * uint(num_ciphersuites)
    // compression methods
	var num_compressionMethods = uint8(data[offset])
	offset += 1
	p.compressionMethods = make([]uint8, num_compressionMethods)
	for i = 0; i < uint(num_compressionMethods); i++ {
		p.compressionMethods[i] = data[offset+i]
	}
	offset += i

	// TODO: add support for extensions

	return nil
}
