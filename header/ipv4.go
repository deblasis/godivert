package header

import (
	"encoding/binary"
	"fmt"
	"net"
)

// Represents a IPv4 Header
// https://en.wikipedia.org/wiki/IPv4#Header
type IPv4Header struct {
	Raw      []byte
	Modified bool
}

func NewIPv4Header(raw []byte) *IPv4Header {
	hdrLen := (raw[0] & 0xf) << 2
	return &IPv4Header{
		Raw: raw[:hdrLen],
	}
}

func (h *IPv4Header) String() string {
	if h == nil {
		return "<nil>"
	}

	checksum, _ := h.Checksum()
	nextHeader := h.NextHeader()
	return fmt.Sprintf("{\n"+
		"\t\tVersion=%d\n"+
		"\t\tHeaderLen=%d\n"+
		"\t\tTOS=%d\n"+
		"\t\tTotalLen=%d\n"+
		"\t\tID=%#x\n"+
		"\t\tFlags=%#x\n"+
		"\t\tFragOff=%#x\n"+
		"\t\tTTL=%d\n"+
		"\t\tNextHeader=(%d)->%s\n"+
		"\t\tCheckSum=%d\n"+
		"\t\tSrcIP=%v\n"+
		"\t\tDstIP=%v\n"+
		"\t}",
		h.Version(), h.HeaderLen(), h.TOS(), h.TotalLen(), h.ID(), h.Flags(), h.FragOff(), h.TTL(), nextHeader, ProtocolName(nextHeader), checksum, h.SrcIP(), h.DstIP())
}

// Returns the IP Version
func (h *IPv4Header) Version() int {
	return IPv4
}

// Reads the header's bytes and returns its length
func (h *IPv4Header) HeaderLen() uint8 {
	return h.Raw[0] & 0xf << 2
}

// Reads the header's bytes and returns the Type Of Service
func (h *IPv4Header) TOS() uint8 {
	return h.Raw[1]
}

// Reads the header's bytes and returns the total length of the packet
func (h *IPv4Header) TotalLen() uint16 {
	return binary.BigEndian.Uint16(h.Raw[2:4])
}

// Reads the header's bytes and returns the ID
func (h *IPv4Header) ID() uint16 {
	return binary.BigEndian.Uint16(h.Raw[4:6])
}

// Reads the header's bytes and returns the flags
func (h *IPv4Header) Flags() uint8 {
	return h.Raw[6] >> 5
}

// Reads the header's bytes and returns the Fragment Offset
func (h *IPv4Header) FragOff() uint16 {
	return binary.BigEndian.Uint16(h.Raw[6:8]) & 0x7f
}

// Reads the header's bytes and returns the Time To Live of the packet
func (h *IPv4Header) TTL() uint8 {
	return h.Raw[8]
}

// Reads the header's bytes and returns the protocol number
func (h *IPv4Header) NextHeader() uint8 {
	return h.Raw[9]
}

// Reads the header's bytes and returns the Checksum
func (h *IPv4Header) Checksum() (uint16, error) {
	return uint16(h.Raw[10])<<8 | uint16(h.Raw[11]), nil
}

// Reads the header's bytes and returns the source IP
func (h *IPv4Header) SrcIP() net.IP {
	// Reuse static IP to avoid allocations
	ip := make([]byte, net.IPv4len)
	copy(ip, h.Raw[IPv4_SRCIP_OFFSET:IPv4_SRCIP_OFFSET+net.IPv4len])
	return ip
}

// Reads the header's bytes and returns the destination IP
func (h *IPv4Header) DstIP() net.IP {
	ip := make([]byte, net.IPv4len)
	copy(ip, h.Raw[IPv4_DSTIP_OFFSET:IPv4_DSTIP_OFFSET+net.IPv4len])
	return ip
}

// Reads the header's bytes and returns the options as a byte slice if they exist or nil
func (h *IPv4Header) Options() []byte {
	hdrLen := h.HeaderLen()
	if hdrLen == 20 {
		return nil
	}

	return h.Raw[IPv4HeaderLen:hdrLen]
}

// Sets the source IP of the packet
func (h *IPv4Header) SetSrcIP(ip net.IP) {
	h.Modified = true
	if ip4 := ip.To4(); ip4 != nil {
		h.Raw[IPv4_SRCIP_OFFSET] = ip4[0]
		h.Raw[IPv4_SRCIP_OFFSET+1] = ip4[1]
		h.Raw[IPv4_SRCIP_OFFSET+2] = ip4[2]
		h.Raw[IPv4_SRCIP_OFFSET+3] = ip4[3]
	}
}

// Sets the destination IP of the packet
func (h *IPv4Header) SetDstIP(ip net.IP) {
	h.Modified = true
	if ip4 := ip.To4(); ip4 != nil {
		copy(h.Raw[IPv4_DSTIP_OFFSET:IPv4_DSTIP_OFFSET+net.IPv4len], ip4)
	}
}

// Returns true if the header has been modified
func (h *IPv4Header) NeedNewChecksum() bool {
	return h.Modified
}
