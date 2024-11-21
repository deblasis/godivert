package godivert

import (
	"encoding/binary"
	"fmt"
)

// Represents a WinDivertAddress struct
// See : https://reqrypt.org/windivert-doc.html#divert_address
type WinDivertAddress struct {
	Timestamp int64
	IfIdx     uint32
	SubIfIdx  uint32
	Flags     uint8
	Reserved1 uint8
	Reserved2 uint16
	Reserved3 uint32
}

// NewWinDivertAddress creates a new WinDivertAddress with default values
func NewWinDivertAddress() *WinDivertAddress {
	return &WinDivertAddress{
		Timestamp: 0,
		IfIdx:     0,
		SubIfIdx:  0,
		Flags:     0,
		Reserved1: 0,
		Reserved2: 0,
		Reserved3: 0,
	}
}

// Add helper methods to handle flags through Flags field
func (w *WinDivertAddress) SetFlags(flags uint8) {
	w.Flags = (w.Flags & 0xF0) | (flags & 0x0F)
}

func (w *WinDivertAddress) GetFlags() uint8 {
	return w.Flags & 0x0F
}

func (w *WinDivertAddress) SetLayer(layer uint8) {
	w.Flags = (w.Flags & 0x0F) | (layer << 4)
}

func (w *WinDivertAddress) GetLayer() uint8 {
	return w.Flags >> 4
}

// Returns the direction of the packet
// WinDivertDirectionInbound (true) for inbounds packets
// WinDivertDirectionOutbounds (false) for outbounds packets
func (w *WinDivertAddress) Direction() Direction {
	return Direction(w.Flags&0x1 == 1)
}

// Returns true if the packet is a loopback packet
func (w *WinDivertAddress) Loopback() bool {
	return (w.Flags>>1)&0x1 == 1
}

// Returns true if the packet is an impostor
func (w *WinDivertAddress) Impostor() bool {
	return (w.Flags>>2)&0x1 == 1
}

// Returns true if the packet uses a pseudo IP checksum
func (w *WinDivertAddress) PseudoIPChecksum() bool {
	return (w.Flags>>3)&0x1 == 1
}

// Returns true if the packet uses a pseudo TCP checksum
func (w *WinDivertAddress) PseudoTCPChecksum() bool {
	return (w.Flags>>4)&0x1 == 1
}

// Returns true if the packet uses a pseudo UDP checksum
func (w *WinDivertAddress) PseudoUDPChecksum() bool {
	return (w.Flags>>5)&0x1 == 1
}

func (w *WinDivertAddress) String() string {
	return fmt.Sprintf("{\n"+
		"\t\tTimestamp=%d\n"+
		"\t\tInteface={IfIdx=%d SubIfIdx=%d}\n"+
		"\t\tDirection=%v\n"+
		"\t\tLoopback=%t\n"+
		"\t\tImpostor=%t\n"+
		"\t\tPseudoChecksum={IP=%t TCP=%t UDP=%t}\n"+
		"\t}",
		w.Timestamp, w.IfIdx, w.SubIfIdx, w.Direction(), w.Loopback(), w.Impostor(),
		w.PseudoIPChecksum(), w.PseudoTCPChecksum(), w.PseudoUDPChecksum())
}

// Size returns the binary size of WinDivertAddress
func (w *WinDivertAddress) Size() int {
	return 24 // 8 + 4 + 4 + 1 + 1 + 2 + 4 bytes
}

// MarshalBinary implements the encoding.BinaryMarshaler interface
func (w *WinDivertAddress) MarshalBinary() ([]byte, error) {
	buf := make([]byte, w.Size())
	offset := 0

	// Write Timestamp (int64 - 8 bytes)
	binary.LittleEndian.PutUint64(buf[offset:], uint64(w.Timestamp))
	offset += 8

	// Write IfIdx (uint32 - 4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], w.IfIdx)
	offset += 4

	// Write SubIfIdx (uint32 - 4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], w.SubIfIdx)
	offset += 4

	// Write Flags (uint8 - 1 byte)
	buf[offset] = w.Flags
	offset++

	// Write Reserved1 (uint8 - 1 byte)
	buf[offset] = w.Reserved1
	offset++

	// Write Reserved2 (uint16 - 2 bytes)
	binary.LittleEndian.PutUint16(buf[offset:], w.Reserved2)
	offset += 2

	// Write Reserved3 (uint32 - 4 bytes)
	binary.LittleEndian.PutUint32(buf[offset:], w.Reserved3)

	return buf, nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface
func (w *WinDivertAddress) UnmarshalBinary(data []byte) error {
	if len(data) < w.Size() {
		return fmt.Errorf("data too short for WinDivertAddress: got %d bytes, want %d", len(data), w.Size())
	}

	offset := 0

	// Read Timestamp
	w.Timestamp = int64(binary.LittleEndian.Uint64(data[offset:]))
	offset += 8

	// Read IfIdx
	w.IfIdx = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Read SubIfIdx
	w.SubIfIdx = binary.LittleEndian.Uint32(data[offset:])
	offset += 4

	// Read Flags
	w.Flags = data[offset]
	offset++

	// Read Reserved1
	w.Reserved1 = data[offset]
	offset++

	// Read Reserved2
	w.Reserved2 = binary.LittleEndian.Uint16(data[offset:])
	offset += 2

	// Read Reserved3
	w.Reserved3 = binary.LittleEndian.Uint32(data[offset:])

	return nil
}
