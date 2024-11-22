package godivert

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/deblasis/godivert/header"
)

// Represents a packet
type Packet struct {
	Raw       []byte
	Addr      *WinDivertAddress
	PacketLen uint

	IpHdr      header.IPHeader
	NextHeader header.ProtocolHeader

	ipVersion      int
	hdrLen         int
	nextHeaderType uint8

	parsed bool
}

// Parse the packet's headers
func (p *Packet) ParseHeaders() {
	if p.parsed {
		return
	}

	// Handle empty packets
	if len(p.Raw) == 0 {
		p.ipVersion = 0
		p.hdrLen = 0
		p.nextHeaderType = 0
		p.IpHdr = nil
		p.NextHeader = nil
		p.parsed = true
		return
	}

	p.ipVersion = int(p.Raw[0] >> 4)
	if p.ipVersion == 4 {
		p.hdrLen = int((p.Raw[0] & 0xf) << 2)
		p.nextHeaderType = p.Raw[9]
		p.IpHdr = header.NewIPv4Header(p.Raw)
	} else {
		p.hdrLen = 40
		p.nextHeaderType = p.Raw[6]
		p.IpHdr = header.NewIPv6Header(p.Raw)
	}

	// Ensure we have enough bytes for the next header
	if len(p.Raw) <= p.hdrLen {
		p.NextHeader = nil
		p.parsed = true
		return
	}

	// Get the payload after IP header
	payload := p.Raw[p.hdrLen:]

	switch p.nextHeaderType {
	case header.ICMPv4:
		if len(payload) >= header.ICMPv4HeaderLen {
			p.NextHeader = header.NewICMPv4Header(payload)
		}
	case header.TCP:
		if len(payload) >= header.TCPHeaderLen {
			p.NextHeader = header.NewTCPHeader(payload)
		}
	case header.UDP:
		if len(payload) >= header.UDPHeaderLen {
			p.NextHeader = header.NewUDPHeader(payload)
		}
	case header.ICMPv6:
		if len(payload) >= header.ICMPv6HeaderLen {
			p.NextHeader = header.NewICMPv6Header(payload)
		}
	default:
		// Protocol not implemented or unknown
		p.NextHeader = nil
	}

	p.parsed = true
}

func (p *Packet) String() string {
	p.VerifyParsed()

	nextHeaderType := p.NextHeaderType()
	return fmt.Sprintf("Packet {\n"+
		"\tIPHeader=%v\n"+
		"\tNextHeaderType=(%d)->%s\n"+
		"\tNextHeader: %v\n"+
		"\tWinDivertAddr=%v\n"+
		"\tRawData=%v\n"+
		"}",
		p.IpHdr, nextHeaderType, header.ProtocolName(nextHeaderType), p.NextHeader, p.Addr, p.Raw)
}

// Returns the version of the IP protocol
// Shortcut for ipHdr.Version()
func (p *Packet) IpVersion() int {
	return p.ipVersion
}

// Returns the IP Protocol number of the next Header
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
func (p *Packet) NextHeaderType() uint8 {
	p.VerifyParsed()

	return p.nextHeaderType
}

// Returns the source IP of the packet
// Shortcut for IpHdr.SrcIP()
func (p *Packet) SrcIP() net.IP {
	if !p.parsed {
		p.ParseHeaders()
	}
	// Safety check after parsing
	if len(p.Raw) < 16 { // Minimum size needed for IPv4 header
		return nil
	}
	// Direct array access for IPv4
	if p.ipVersion == 4 {
		return net.IPv4(p.Raw[12], p.Raw[13], p.Raw[14], p.Raw[15])
	}
	// IPv6 needs more complex handling
	return p.IpHdr.SrcIP()
}

// Sets the source IP of the packet
func (p *Packet) SetSrcIP(ip net.IP) {
	if !p.parsed {
		p.ParseHeaders()
	}
	// Fast path for IPv4 (most common case)
	if p.ipVersion == 4 {
		// Direct byte access for both formats
		if len(ip) == 16 {
			p.Raw[header.IPv4_SRCIP_OFFSET] = ip[12]
			p.Raw[header.IPv4_SRCIP_OFFSET+1] = ip[13]
			p.Raw[header.IPv4_SRCIP_OFFSET+2] = ip[14]
			p.Raw[header.IPv4_SRCIP_OFFSET+3] = ip[15]
		} else {
			p.Raw[header.IPv4_SRCIP_OFFSET] = ip[0]
			p.Raw[header.IPv4_SRCIP_OFFSET+1] = ip[1]
			p.Raw[header.IPv4_SRCIP_OFFSET+2] = ip[2]
			p.Raw[header.IPv4_SRCIP_OFFSET+3] = ip[3]
		}
		// Skip type assertion - direct field access
		p.IpHdr.(*header.IPv4Header).Modified = true
		return
	}
	p.IpHdr.SetSrcIP(ip)
}

// Returns the destination IP of the packet
// Shortcut for IpHdr.DstIP()
func (p *Packet) DstIP() net.IP {
	if !p.parsed {
		p.ParseHeaders()
	}
	// Safety check after parsing
	if len(p.Raw) < 20 { // Minimum size needed for IPv4 header
		return nil
	}
	// Direct array access for IPv4
	if p.ipVersion == 4 {
		return net.IPv4(p.Raw[16], p.Raw[17], p.Raw[18], p.Raw[19])
	}
	// IPv6 needs more complex handling
	return p.IpHdr.DstIP()
}

// Sets the destination IP of the packet
func (p *Packet) SetDstIP(ip net.IP) {
	if !p.parsed {
		p.ParseHeaders()
	}
	// Fast path for IPv4 (most common case)
	if p.ipVersion == 4 {
		// Direct byte access for both formats
		if len(ip) == 16 {
			p.Raw[header.IPv4_DSTIP_OFFSET] = ip[12]
			p.Raw[header.IPv4_DSTIP_OFFSET+1] = ip[13]
			p.Raw[header.IPv4_DSTIP_OFFSET+2] = ip[14]
			p.Raw[header.IPv4_DSTIP_OFFSET+3] = ip[15]
		} else {
			p.Raw[header.IPv4_DSTIP_OFFSET] = ip[0]
			p.Raw[header.IPv4_DSTIP_OFFSET+1] = ip[1]
			p.Raw[header.IPv4_DSTIP_OFFSET+2] = ip[2]
			p.Raw[header.IPv4_DSTIP_OFFSET+3] = ip[3]
		}
		// Skip type assertion - direct field access
		p.IpHdr.(*header.IPv4Header).Modified = true
		return
	}
	p.IpHdr.SetDstIP(ip)
}

// Returns the source port of the packet
// Shortcut for NextHeader.SrcPort()
func (p *Packet) SrcPort() (uint16, error) {
	if !p.parsed {
		p.ParseHeaders()
	}
	if p.NextHeader == nil {
		return 0, fmt.Errorf("cannot get source port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}
	// Safety check for minimum header size
	if len(p.Raw) < p.hdrLen+2 {
		return 0, fmt.Errorf("packet too short for source port")
	}
	// Fast path for TCP/UDP
	if p.nextHeaderType == header.TCP || p.nextHeaderType == header.UDP {
		return binary.BigEndian.Uint16(p.Raw[p.hdrLen : p.hdrLen+2]), nil
	}
	return p.NextHeader.SrcPort()
}

// Sets the source port of the packet
// Shortcut for NextHeader.SetSrcPort()
func (p *Packet) SetSrcPort(port uint16) error {
	if !p.parsed {
		p.ParseHeaders()
	}
	if p.NextHeader == nil {
		return fmt.Errorf("cannot change source port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}
	// Safety check for minimum header size
	if len(p.Raw) < p.hdrLen+2 {
		return fmt.Errorf("packet too short for source port")
	}
	// Fast path for TCP/UDP
	if p.nextHeaderType == header.TCP || p.nextHeaderType == header.UDP {
		p.Raw[p.hdrLen] = byte(port >> 8)
		p.Raw[p.hdrLen+1] = byte(port)
		p.NextHeader.(*header.TCPHeader).Modified = true
		return nil
	}
	return p.NextHeader.SetSrcPort(port)
}

// Returns the destination port of the packet
// Shortcut for NextHeader.DstPort()
func (p *Packet) DstPort() (uint16, error) {
	if !p.parsed {
		p.ParseHeaders()
	}
	if p.NextHeader == nil {
		return 0, fmt.Errorf("cannot get destination port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}
	// Safety check for minimum header size
	if len(p.Raw) < p.hdrLen+4 {
		return 0, fmt.Errorf("packet too short for destination port")
	}
	// Fast path for TCP/UDP
	if p.nextHeaderType == header.TCP || p.nextHeaderType == header.UDP {
		return binary.BigEndian.Uint16(p.Raw[p.hdrLen+2 : p.hdrLen+4]), nil
	}
	return p.NextHeader.DstPort()
}

// Sets the destination port of the packet
// Shortcut for NextHeader.SetDstPort()
func (p *Packet) SetDstPort(port uint16) error {
	if !p.parsed {
		p.ParseHeaders()
	}
	if p.NextHeader == nil {
		return fmt.Errorf("cannot change destination port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}
	// Safety check for minimum header size
	if len(p.Raw) < p.hdrLen+4 {
		return fmt.Errorf("packet too short for destination port")
	}
	// Fast path for TCP/UDP
	if p.nextHeaderType == header.TCP || p.nextHeaderType == header.UDP {
		p.Raw[p.hdrLen+2] = byte(port >> 8)
		p.Raw[p.hdrLen+3] = byte(port)
		if p.nextHeaderType == header.TCP {
			p.NextHeader.(*header.TCPHeader).Modified = true
		} else {
			p.NextHeader.(*header.UDPHeader).Modified = true
		}
		return nil
	}
	return p.NextHeader.SetDstPort(port)
}

// Returns the name of the protocol
func (p *Packet) NextHeaderProtocolName() string {
	return header.ProtocolName(p.NextHeaderType())
}

// Inject the packet on the Network Stack
// If the packet has been modified calls WinDivertHelperCalcChecksum to get a new checksum
func (p *Packet) Send(wd *WinDivertHandle) (uint, error) {
	if p.parsed && (p.IpHdr.NeedNewChecksum() || p.NextHeader != nil && p.NextHeader.NeedNewChecksum()) {
		wd.HelperCalcChecksum(p)
	}
	return wd.Send(p)
}

// Recalculate the packet's checksum
// Shortcut for WinDivertHelperCalcChecksum
func (p *Packet) CalcNewChecksum(wd *WinDivertHandle) {
	wd.HelperCalcChecksum(p)
}

// Check if the headers have already been parsed and call ParseHeaders() if not
func (p *Packet) VerifyParsed() {
	if !p.parsed {
		p.ParseHeaders()
	}
}

// Returns the Direction of the packet
// WinDivertDirectionInbound (true) for inbound Packets
// WinDivertDirectionOutbound (false) for outbound packets
// Shortcut for Addr.Direction()
func (p *Packet) Direction() Direction {
	return p.Addr.Direction()
}

// Check the packet with the filter
// Returns true if the packet matches the filter
func (p *Packet) EvalFilter(filter string) (bool, error) {
	return HelperEvalFilter(p, filter)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (p *Packet) MarshalBinary() ([]byte, error) {
	size := header.MarshalHeaderSize + len(p.Raw) + header.AddressSize

	// Get buffer from optimized pool
	mb, pooled := GetMarshalBuffer(size)
	defer PutMarshalBuffer(mb, pooled)

	// Write header directly to fixed buffer
	binary.LittleEndian.PutUint32(mb.hdr[0:], uint32(p.PacketLen))
	binary.LittleEndian.PutUint32(mb.hdr[4:], uint32(len(p.Raw)))
	mb.hdr[8] = boolToByte(p.parsed)

	// Copy header
	copy(mb.buf[0:], mb.hdr[:])
	offset := header.MarshalHeaderSize

	// Copy packet data
	copy(mb.buf[offset:], p.Raw)
	offset += len(p.Raw)

	// Marshal address
	addrBytes, err := p.Addr.MarshalBinary()
	if err != nil {
		return nil, err
	}
	copy(mb.buf[offset:], addrBytes)

	// Create final result with single allocation
	result := make([]byte, size)
	copy(result, mb.buf)
	return result, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (p *Packet) UnmarshalBinary(data []byte) error {
	if len(data) < header.MarshalHeaderSize {
		return fmt.Errorf("data too short for packet unmarshaling: need at least %d bytes, got %d",
			header.MarshalHeaderSize, len(data))
	}

	// Read header directly
	p.PacketLen = uint(binary.LittleEndian.Uint32(data))
	rawLen := binary.LittleEndian.Uint32(data[4:])
	p.parsed = false // Force reparse
	offset := header.MarshalHeaderSize

	// Validate sizes
	if rawLen > MaxPacketSize {
		return fmt.Errorf("invalid raw packet size: %d (max allowed: %d)", rawLen, MaxPacketSize)
	}

	remainingLen := len(data) - offset
	if remainingLen < int(rawLen)+header.AddressSize {
		return fmt.Errorf("data too short: need %d bytes, got %d",
			int(rawLen)+header.AddressSize, remainingLen)
	}

	// Reuse or allocate Raw buffer
	if p.Raw == nil || cap(p.Raw) < int(rawLen) {
		p.Raw = make([]byte, rawLen)
	} else {
		p.Raw = p.Raw[:rawLen]
	}

	// Single copy for packet data
	copy(p.Raw, data[offset:offset+int(rawLen)])
	offset += int(rawLen)

	// Initialize address if needed
	if p.Addr == nil {
		p.Addr = NewWinDivertAddress()
	}

	// Unmarshal address directly
	if err := p.Addr.UnmarshalBinary(data[offset:]); err != nil {
		return fmt.Errorf("failed to unmarshal WinDivertAddress: %w", err)
	}

	// Always parse headers after unmarshaling
	p.ParseHeaders()

	return nil
}

// Add helper method to get a packet from pool
func GetPacket() *Packet {
	p := packetPool.Get().(*Packet)
	p.Reset()
	return p
}

// Add helper method to return packet to pool
func (p *Packet) Release() {
	p.Reset()
	packetPool.Put(p)
}

// boolToByte converts a bool to a byte (0 or 1)
func boolToByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// Reset resets the packet to its zero state for reuse
func (p *Packet) Reset() {
	if p.Raw != nil {
		p.Raw = p.Raw[:0]
	}
	p.PacketLen = 0
	p.parsed = false
	p.ipVersion = 0
	p.hdrLen = 0
	p.nextHeaderType = 0
	p.IpHdr = nil
	p.NextHeader = nil

	// Reset address if it exists
	if p.Addr != nil {
		p.Addr.Timestamp = 0
		p.Addr.IfIdx = 0
		p.Addr.SubIfIdx = 0
		p.Addr.Flags = 0
		p.Addr.Reserved1 = 0
		p.Addr.Reserved2 = 0
		p.Addr.Reserved3 = 0
	}
}

// Only parse what's needed
func (p *Packet) ensureIPHeader() {
	if p.IpHdr == nil {
		p.parseIPHeader()
	}
}

// Process multiple packets at once
func ProcessPacketBatch(packets []*Packet) {
	// ... batch processing logic
}

// Parse only IP header
func (p *Packet) parseIPHeader() {
	if len(p.Raw) == 0 {
		p.ipVersion = 0
		p.hdrLen = 0
		p.nextHeaderType = 0
		p.IpHdr = nil
		return
	}

	p.ipVersion = int(p.Raw[0] >> 4)
	if p.ipVersion == 4 {
		p.hdrLen = int((p.Raw[0] & 0xf) << 2)
		p.nextHeaderType = p.Raw[9]
		p.IpHdr = header.NewIPv4Header(p.Raw)
	} else {
		p.hdrLen = 40
		p.nextHeaderType = p.Raw[6]
		p.IpHdr = header.NewIPv6Header(p.Raw)
	}
}
