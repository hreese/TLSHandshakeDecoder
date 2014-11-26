package TLSHandshakeDecoder

import (
	_ "bytes"
	"errors"
	"fmt"
)

type TLSHandshake struct {
	HandshakeType uint8
	length        uint32
	body          []byte
}

type TLSClientHello struct {
	// HandshakeType // 1
	length  uint32   // 3
	version uint16   // 2
	random  [28]byte // 28
	//sessionid          []byte   // 1+v
	ciphersuites       []uint16 // 2+v
	compressionMethods []uint8  // 1+v
	// TODO: add support for extensions
}

func DecodeHandshake(p *TLSHandshake, data []byte) error {
	if len(data) < 4 {
		return errors.New("Handshake body too short (<4).")
	}

	p.HandshakeType = uint8(data[0])
	p.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])

	p.body = make([]byte, p.length)
	l := copy(p.body, data[4:4+p.length])
	if l < int(p.length) {
		return fmt.Errorf("Payload to short: copied %d, expected %d.", l, p.length)
	}

	return nil
}

func DecodeClientHello(p *TLSClientHello, data []byte) error {
	if len(data) < 38 {
		return errors.New("Handshake body too short (<4).")
	}

	HandshakeType := data[0]
	if HandshakeType != 0x01 {
		return fmt.Errorf("Not a ClientHello packet (type is %x, expected 0x01)", HandshakeType)
	}

	p.length = uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	p.version = uint16(data[4])<<8 | uint16(data[5])
	//copy(p.random, data[6:6+28]) // TODO: verify success
	sessionid_length := data[34]
	var offset uint = 1 + 3 + 2 + 28 + 1 + uint(sessionid_length)
	var num_ciphersuites uint16 = (uint16(data[offset])<<8 | uint16(data[offset+1])) / 2
	offset += 2
	p.ciphersuites = make([]uint16, num_ciphersuites)
	var i uint
	for i = 0; i < uint(num_ciphersuites); i++ {
		p.ciphersuites[i] = uint16(data[offset+2*i])<<8 | uint16(data[offset+2*i+1])
	}

	// TODO: add support for compressionMethods & extensions

	return nil
}
