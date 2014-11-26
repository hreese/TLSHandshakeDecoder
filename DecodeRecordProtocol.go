package TLSHandshakeDecoder

import (
    _ "bytes"
    "errors"
    "fmt"
)

type TLSRecordLayer struct {
	contentType uint8
	version     uint16
	length      uint16
	fragment    []byte
}

func DecodeRecord(p *TLSRecordLayer, data []byte) error {
    if len(data) < 5 {
        return errors.New("Payload too short to be a TLS packet.")
    }

    p.contentType = uint8(data[0])
    p.version = uint16(data[1])<<8 | uint16(data[2])
    p.length = uint16(data[3])<<8 | uint16(data[4])

    p.fragment = make([]byte, p.length)
    l := copy (p.fragment, data[5:5+p.length])
    if l < int(p.length) {
        return fmt.Errorf("Payload to short: copied %d, expected %d.", l, p.length)
    }

    return nil
}
