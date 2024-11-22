package header

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// Represents a IPv6 header
// https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
type IPv6Header struct {
	Raw      []byte
	Modified bool
}

func NewIPv6Header(raw []byte) *IPv6Header {
	return &IPv6Header{
		Raw: raw[:IPv6HeaderLen],
	}
}

func (h *IPv6Header) String() string {
	if h == nil {
		return "<nil>"
	}
	nextHeader := h.NextHeader()
	return fmt.Sprintf("{\n"+
		"\t\tVersion=%d\n"+
		"\t\tHeaderLen=%d\n"+
		"\t\tTrafficClass=%#x\n"+
		"\t\tFlowLabel=%#x\n"+
		"\t\tPayloadLen=%d\n"+
		"\t\tNextHeader=(%d)->%s\n"+
		"\t\tHopLimit=%d\n"+
		"\t\tSrcIP=%v\n"+
		"\t\tDstIP=%v\n"+
		"}",
		h.Version(), h.HeaderLen(), h.TrafficClass(), h.FlowLabel(), h.PayloadLen(), nextHeader, ProtocolName(nextHeader), h.HopLimit(), h.SrcIP(), h.DstIP())
}

// Returns the IP Version
func (h *IPv6Header) Version() int {
	return IPv6
}

// Returns the length of the header in bytes (40 bytes)
func (h *IPv6Header) HeaderLen() uint8 {
	return IPv6HeaderLen
}

// Reads the header's bytes and returns the traffic class
func (h *IPv6Header) TrafficClass() uint8 {
	return (h.Raw[0]&0xf)<<4 | (h.Raw[1] >> 4)
}

// Reads the header's bytes and returns the flow label
func (h *IPv6Header) FlowLabel() uint32 {
	return uint32(h.Raw[1]&0xf)<<16 | uint32(h.Raw[2])<<8 | uint32(h.Raw[3])
}

// Reads the header's bytes and returns the length of the payload
func (h *IPv6Header) PayloadLen() uint16 {
	return binary.BigEndian.Uint16(h.Raw[4:6])
}

// Reads the header's bytes and returns the protocol number
func (h *IPv6Header) NextHeader() uint8 {
	return h.Raw[IPv6_PROTO_OFFSET]
}

// Reads the header's bytes and returns the hop limit
func (h *IPv6Header) HopLimit() uint8 {
	return h.Raw[7]
}

// Reads the header's bytes and returns the source IP
func (h *IPv6Header) SrcIP() net.IP {
	if h.Raw[8] == 0 && h.Raw[9] == 0 && h.Raw[10] == 0 && h.Raw[11] == 0 {
		return net.IPv6zero
	}
	return net.IP(h.Raw[8:24])
}

// Reads the header's bytes and returns the destination IP
func (h *IPv6Header) DstIP() net.IP {
	if isZeroIPFast(h.Raw[24:40]) {
		return net.IPv6zero
	}
	ip := make([]byte, net.IPv6len)
	copy(ip, h.Raw[24:40])
	return ip
}

// Optimized zero IP check using uint64
func isZeroIPFast(ip []byte) bool {
	// Check 16 bytes in 2 uint64 chunks
	p1 := binary.BigEndian.Uint64(ip[0:8])
	p2 := binary.BigEndian.Uint64(ip[8:16])
	return p1 == 0 && p2 == 0
}

// Sets the source IP of the packet
func (h *IPv6Header) SetSrcIP(ip net.IP) {
	h.Modified = true
	if len(ip) == net.IPv6len {
		// Direct byte access for IPv6
		for i := 0; i < 16; i++ {
			h.Raw[8+i] = ip[i]
		}
	} else {
		// IPv4-mapped IPv6 fast path
		h.Raw[8] = 0
		h.Raw[9] = 0
		h.Raw[10] = 0xff
		h.Raw[11] = 0xff
		h.Raw[12] = ip[12]
		h.Raw[13] = ip[13]
		h.Raw[14] = ip[14]
		h.Raw[15] = ip[15]
	}
}

// Sets the destination IP of the packet
func (h *IPv6Header) SetDstIP(ip net.IP) {
	h.Modified = true
	if len(ip) == net.IPv6len {
		// Direct copy for IPv6
		copy(h.Raw[24:40], ip)
	} else {
		// Fast path for IPv4-mapped IPv6
		copy(h.Raw[24:40], net.IPv4(ip[12], ip[13], ip[14], ip[15]).To16())
	}
}

// Always returns 0 and an error as IPv6 has no checksum
func (h *IPv6Header) Checksum() (uint16, error) {
	return 0, errors.New("IPv6 has no checksum field")
}

// Always returns false as IPv6 has no checksum
func (h *IPv6Header) NeedNewChecksum() bool {
	return false
}
