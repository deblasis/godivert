package header

const (
	IPv4HeaderLen    = 20
	MaxIPv4HeaderLen = 60
	IPv6HeaderLen    = 40
	TCPHeaderLen     = 20
	MaxTCPHeaderLen  = 60
	UDPHeaderLen     = 8
	ICMPv4HeaderLen  = 8
	ICMPv6HeaderLen  = 8

	ICMPv4 = 1
	TCP    = 6
	UDP    = 17
	ICMPv6 = 58

	IPv4 = 4
	IPv6 = 6

	// Fixed sizes for marshaling
	AddressSize       = 24 // WinDivertAddress fixed size
	MarshalHeaderSize = 9  // PacketLen(4) + RawLen(4) + parsed(1)
)
