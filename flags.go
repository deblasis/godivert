package godivert

type Flags uint64

const (
	// Packet sniffing mode - packets will continue to their destination
	FlagSniff Flags = 0x0001

	// Packet dropping mode - matching packets will be dropped
	FlagDrop Flags = 0x0002

	// Receive-only mode - packets can only be read, not injected
	FlagRecvOnly Flags = 0x0004
	FlagReadOnly       = FlagRecvOnly // Alias for FlagRecvOnly

	// Send-only mode - packets can only be injected, not read
	FlagSendOnly  Flags = 0x0008
	FlagWriteOnly       = FlagSendOnly // Alias for FlagSendOnly

	// Skip driver installation check
	FlagNoInstall Flags = 0x0010

	// Handle IP fragments
	FlagFragments Flags = 0x0020
)

// Has checks if the flags contain all the given flags
func (f Flags) Has(flags Flags) bool {
	return f&flags == flags
}

// Add adds the given flags
func (f *Flags) Add(flags Flags) {
	*f |= flags
}

// Remove removes the given flags
func (f *Flags) Remove(flags Flags) {
	*f &^= flags
}

// Clear removes all flags
func (f *Flags) Clear() {
	*f = 0
}

// IsValid checks if the flags combination is valid according to WinDivert rules
func (f Flags) IsValid() bool {
	// Can't have both Sniff and Drop
	if f.Has(FlagSniff | FlagDrop) {
		return false
	}

	// Can't have both RecvOnly and SendOnly
	if f.Has(FlagRecvOnly | FlagSendOnly) {
		return false
	}

	return true
}
