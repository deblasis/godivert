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

	// IPv4 header offsets
	IPv4_VERSION_OFFSET  = 0
	IPv4_PROTO_OFFSET    = 9
	IPv4_SRCIP_OFFSET    = 12
	IPv4_DSTIP_OFFSET    = 16
	IPv4_CHECKSUM_OFFSET = 10

	// IPv6 header offsets
	IPv6_PROTO_OFFSET = 6
	IPv6_SRCIP_OFFSET = 8
	IPv6_DSTIP_OFFSET = 24
)
