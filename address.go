package godivert

import "fmt"

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

// Add these constants for Layer values
const (
	LayerNetwork = 0
	LayerForward = 1
	LayerFlow    = 2
	LayerSocket  = 3
	LayerReflect = 4
)

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
