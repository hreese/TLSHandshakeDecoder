package TLSHandshakeDecoder

import (
    _ "bytes"
    "errors"
    "fmt"
)

type TLSHandshake struct {
    HandshakeType uint8
    length uint32
    body []byte
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
