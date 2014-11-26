package TLSHandshakeDecoder

const (
	TypeChangeCypherSpec uint8 = 20
	TypeAlert            uint8 = 21
	TypeHandshake        uint8 = 22
	TypeApplicationData  uint8 = 23
)

const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
)

const (
	HandshakeTypeHelloRequest       uint8 = 0
	HandshakeTypeClientHello        uint8 = 1
	HandshakeTypeServerHello        uint8 = 2
	HandshakeTypeHelloVerifyRequest uint8 = 3
	HandshakeTypeCertificate        uint8 = 11
	HandshakeTypeServerKeyExchange  uint8 = 12
	HandshakeTypeCertificateRequest uint8 = 13
	HandshakeTypeServerHelloDone    uint8 = 14
	HandshakeTypeCertificateVerify  uint8 = 15
	HandshakeTypeClientKeyExchange  uint8 = 16
	HandshakeTypeFinished           uint8 = 20
)

const (
	extensionServerName          uint16 = 0
	extensionStatusRequest       uint16 = 5
	extensionSupportedCurves     uint16 = 10
	extensionSupportedPoints     uint16 = 11
	extensionSignatureAlgorithms uint16 = 13
	extensionHeartbeat           uint16 = 16
	extensionSessionTicket       uint16 = 35
	extensionRenegotiation       uint16 = 0xff01
)
