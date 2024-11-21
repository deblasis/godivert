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
	p.VerifyParsed()

	return p.IpHdr.SrcIP()
}

// Sets the source IP of the packet
// Shortcut for IpHdr.SetSrcIP()
func (p *Packet) SetSrcIP(ip net.IP) {
	p.VerifyParsed()

	p.IpHdr.SetSrcIP(ip)
}

// Returns the destination IP of the packet
// Shortcut for IpHdr.DstIP()
func (p *Packet) DstIP() net.IP {
	p.VerifyParsed()

	return p.IpHdr.DstIP()
}

// Sets the destination IP of the packet
// Shortcut for IpHdr.SetDstIP()
func (p *Packet) SetDstIP(ip net.IP) {
	p.VerifyParsed()

	p.IpHdr.SetDstIP(ip)
}

// Returns the source port of the packet
// Shortcut for NextHeader.SrcPort()
func (p *Packet) SrcPort() (uint16, error) {
	p.VerifyParsed()

	if p.NextHeader == nil {
		return 0, fmt.Errorf("cannot get source port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}

	return p.NextHeader.SrcPort()
}

// Sets the source port of the packet
// Shortcut for NextHeader.SetSrcPort()
func (p *Packet) SetSrcPort(port uint16) error {
	p.VerifyParsed()

	if p.NextHeader == nil {
		return fmt.Errorf("cannot change source port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}

	return p.NextHeader.SetSrcPort(port)

}

// Returns the destination port of the packet
// Shortcut for NextHeader.DstPort()
func (p *Packet) DstPort() (uint16, error) {
	p.VerifyParsed()

	if p.NextHeader == nil {
		return 0, fmt.Errorf("cannot change get port on protocolID=%d, protocol not implemented", p.nextHeaderType)
	}

	return p.NextHeader.DstPort()
}

// Sets the destination port of the packet
// Shortcut for NextHeader.SetDstPort()
func (p *Packet) SetDstPort(port uint16) error {
	p.VerifyParsed()

	if p.NextHeader == nil {
		return fmt.Errorf("cannot change destination port on protocolID=%d, protocol not implemented", p.nextHeaderType)
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
	// Calculate total size needed
	size := 8 + // For PacketLen and rawLen
		1 + // For parsed flag
		len(p.Raw) + // Raw packet data
		p.Addr.Size() // WinDivertAddress size

	// Create buffer with calculated size
	buf := make([]byte, size)
	offset := 0

	// Write PacketLen
	binary.LittleEndian.PutUint32(buf[offset:], uint32(p.PacketLen))
	offset += 4

	// Write Raw length
	binary.LittleEndian.PutUint32(buf[offset:], uint32(len(p.Raw)))
	offset += 4

	// Write parsed flag
	if p.parsed {
		buf[offset] = 1
	}
	offset++

	// Write Raw packet data
	copy(buf[offset:], p.Raw)
	offset += len(p.Raw)

	// Write WinDivertAddress
	addrBytes, err := p.Addr.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal WinDivertAddress: %w", err)
	}
	copy(buf[offset:], addrBytes)

	return buf, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (p *Packet) UnmarshalBinary(data []byte) error {
	if len(data) < 9 { // Minimum size check (8 bytes for lengths + 1 for parsed flag)
		return fmt.Errorf("data too short for packet unmarshaling")
	}

	offset := 0

	// Read PacketLen
	p.PacketLen = uint(binary.LittleEndian.Uint32(data[offset:]))
	offset += 4

	// Read Raw length
	rawLen := binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Read parsed flag
	p.parsed = data[offset] == 1
	offset++

	// Initialize WinDivertAddress before using it
	p.Addr = &WinDivertAddress{}
	addrSize := p.Addr.Size()

	// Verify remaining data length
	if len(data[offset:]) < int(rawLen)+addrSize {
		return fmt.Errorf("data too short for packet content: need %d bytes, got %d", int(rawLen)+addrSize, len(data[offset:]))
	}

	// Read Raw packet data
	p.Raw = make([]byte, rawLen)
	copy(p.Raw, data[offset:offset+int(rawLen)])
	offset += int(rawLen)

	// Read WinDivertAddress
	if err := p.Addr.UnmarshalBinary(data[offset:]); err != nil {
		return fmt.Errorf("failed to unmarshal WinDivertAddress: %w", err)
	}

	// If packet was parsed before serialization, parse it again
	if p.parsed {
		p.ParseHeaders()
	}

	return nil
}
