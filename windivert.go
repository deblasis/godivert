package godivert

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/deblasis/godivert/header"
	"golang.org/x/sys/windows"
)

var (
	winDivertDLL *windows.LazyDLL

	winDivertOpen     *windows.LazyProc
	winDivertClose    *windows.LazyProc
	winDivertRecv     *windows.LazyProc
	winDivertRecvEx   *windows.LazyProc
	winDivertSend     *windows.LazyProc
	winDivertSendEx   *windows.LazyProc
	winDivertShutdown *windows.LazyProc
	winDivertSetParam *windows.LazyProc
	winDivertGetParam *windows.LazyProc

	winDivertHelperParsePacket       *windows.LazyProc
	winDivertHelperParseIPv4Address  *windows.LazyProc
	winDivertHelperParseIPv6Address  *windows.LazyProc
	winDivertHelperFormatIPv4Address *windows.LazyProc
	winDivertHelperFormatIPv6Address *windows.LazyProc
	winDivertHelperCalcChecksums     *windows.LazyProc
	winDivertHelperDecrementTTL      *windows.LazyProc
	winDivertHelperCompileFilter     *windows.LazyProc
	winDivertHelperEvalFilter        *windows.LazyProc
	winDivertHelperFormatFilter      *windows.LazyProc

	winDivertHelperHashPacket      *windows.LazyProc
	winDivertHelperNtohs           *windows.LazyProc
	winDivertHelperNtohl           *windows.LazyProc
	winDivertHelperNtohll          *windows.LazyProc
	winDivertHelperHtons           *windows.LazyProc
	winDivertHelperHtonl           *windows.LazyProc
	winDivertHelperHtonll          *windows.LazyProc
	winDivertHelperNtohIPv6Address *windows.LazyProc
	winDivertHelperHtonIPv6Address *windows.LazyProc

	// Track if DLL is loaded
	isDLLLoaded bool

	// Protect DLL loading/unloading operations
	dllMutex sync.RWMutex
)

// Used to call WinDivert's functions
type WinDivertHandle struct {
	handle uintptr
	open   bool
}

// LoadDLL loads the WinDivert DLL and initializes the proc addresses
func LoadDLL(path64, path32 string) error {
	dllMutex.Lock()
	defer dllMutex.Unlock()

	if isDLLLoaded {
		return nil
	}

	if path64 == "" || path32 == "" {
		return errors.New("LoadDLL: empty DLL path provided")
	}

	var dllPath string
	if runtime.GOARCH == "amd64" {
		dllPath = path64
	} else {
		dllPath = path32
	}

	// Load DLL with detailed error checking
	var err error
	winDivertDLL = windows.NewLazyDLL(dllPath)
	if err = winDivertDLL.Load(); err != nil {
		return fmt.Errorf("failed to load WinDivert DLL: %v", err)
	}

	// Load each proc with error checking
	procs := map[string]**windows.LazyProc{
		// Core functions
		"WinDivertOpen":     &winDivertOpen,
		"WinDivertClose":    &winDivertClose,
		"WinDivertRecv":     &winDivertRecv,
		"WinDivertRecvEx":   &winDivertRecvEx,
		"WinDivertSend":     &winDivertSend,
		"WinDivertSendEx":   &winDivertSendEx,
		"WinDivertShutdown": &winDivertShutdown,
		"WinDivertSetParam": &winDivertSetParam,
		"WinDivertGetParam": &winDivertGetParam,

		// Helper functions
		"WinDivertHelperParsePacket":       &winDivertHelperParsePacket,
		"WinDivertHelperParseIPv4Address":  &winDivertHelperParseIPv4Address,
		"WinDivertHelperParseIPv6Address":  &winDivertHelperParseIPv6Address,
		"WinDivertHelperFormatIPv4Address": &winDivertHelperFormatIPv4Address,
		"WinDivertHelperFormatIPv6Address": &winDivertHelperFormatIPv6Address,
		"WinDivertHelperCalcChecksums":     &winDivertHelperCalcChecksums,
		"WinDivertHelperDecrementTTL":      &winDivertHelperDecrementTTL,
		"WinDivertHelperCompileFilter":     &winDivertHelperCompileFilter,
		"WinDivertHelperEvalFilter":        &winDivertHelperEvalFilter,
		"WinDivertHelperFormatFilter":      &winDivertHelperFormatFilter,
		"WinDivertHelperHashPacket":        &winDivertHelperHashPacket,

		// Byte order conversion helpers
		"WinDivertHelperNtohs":           &winDivertHelperNtohs,
		"WinDivertHelperNtohl":           &winDivertHelperNtohl,
		"WinDivertHelperNtohll":          &winDivertHelperNtohll,
		"WinDivertHelperHtons":           &winDivertHelperHtons,
		"WinDivertHelperHtonl":           &winDivertHelperHtonl,
		"WinDivertHelperHtonll":          &winDivertHelperHtonll,
		"WinDivertHelperNtohIPv6Address": &winDivertHelperNtohIPv6Address,
		"WinDivertHelperHtonIPv6Address": &winDivertHelperHtonIPv6Address,
	}

	// Clear all procs before loading new ones
	clearAllProcs()

	for name, proc := range procs {
		*proc = winDivertDLL.NewProc(name)
		if err = (*proc).Find(); err != nil {
			// Just clear procs and return error, don't call UnloadDLL
			clearAllProcs()
			winDivertDLL = nil
			isDLLLoaded = false
			return fmt.Errorf("failed to find %s: %v", name, err)
		}
	}

	isDLLLoaded = true
	return nil
}

// Add this helper function to clear all procs
func clearAllProcs() {
	// Core functions
	winDivertOpen = nil
	winDivertClose = nil
	winDivertRecv = nil
	winDivertRecvEx = nil
	winDivertSend = nil
	winDivertSendEx = nil
	winDivertShutdown = nil
	winDivertSetParam = nil
	winDivertGetParam = nil

	// Helper functions
	winDivertHelperParsePacket = nil
	winDivertHelperParseIPv4Address = nil
	winDivertHelperParseIPv6Address = nil
	winDivertHelperFormatIPv4Address = nil
	winDivertHelperFormatIPv6Address = nil
	winDivertHelperCalcChecksums = nil
	winDivertHelperDecrementTTL = nil
	winDivertHelperCompileFilter = nil
	winDivertHelperEvalFilter = nil
	winDivertHelperFormatFilter = nil
	winDivertHelperHashPacket = nil

	// Byte order conversion helpers
	winDivertHelperNtohs = nil
	winDivertHelperNtohl = nil
	winDivertHelperNtohll = nil
	winDivertHelperHtons = nil
	winDivertHelperHtonl = nil
	winDivertHelperHtonll = nil
	winDivertHelperNtohIPv6Address = nil
	winDivertHelperHtonIPv6Address = nil
}

// CheckDLL verifies that the WinDivert driver is installed and accessible
func CheckDLL() error {
	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if !isDLLLoaded {
		return errors.New("WinDivert DLL not loaded")
	}

	// Verify driver is installed and accessible
	handle, _, err := winDivertOpen.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("false"))),
		uintptr(LayerNetwork),
		0,
		0)

	if handle == 0 {
		return fmt.Errorf("failed to open test handle: %v (this often means the WinDivert driver isn't properly installed)", err)
	}

	// Close test handle
	winDivertClose.Call(handle)
	return nil
}

// UnloadDLL cleans up resources associated with the WinDivert DLL
func UnloadDLL() error {
	dllMutex.Lock()
	defer dllMutex.Unlock()

	if !isDLLLoaded {
		return nil
	}

	// Reset proc addresses to nil
	winDivertOpen = nil
	winDivertClose = nil
	winDivertRecv = nil
	winDivertRecvEx = nil
	winDivertSend = nil
	winDivertSendEx = nil
	winDivertShutdown = nil
	winDivertSetParam = nil
	winDivertGetParam = nil

	winDivertHelperParsePacket = nil
	winDivertHelperParseIPv4Address = nil
	winDivertHelperParseIPv6Address = nil
	winDivertHelperFormatIPv4Address = nil
	winDivertHelperFormatIPv6Address = nil
	winDivertHelperCalcChecksums = nil
	winDivertHelperDecrementTTL = nil
	winDivertHelperCompileFilter = nil
	winDivertHelperEvalFilter = nil
	winDivertHelperFormatFilter = nil

	winDivertHelperHashPacket = nil
	winDivertHelperNtohs = nil
	winDivertHelperNtohl = nil
	winDivertHelperNtohll = nil
	winDivertHelperHtons = nil
	winDivertHelperHtonl = nil
	winDivertHelperHtonll = nil
	winDivertHelperNtohIPv6Address = nil
	winDivertHelperHtonIPv6Address = nil

	// Clear DLL reference
	winDivertDLL = nil
	isDLLLoaded = false

	// Give Windows time to cleanup
	time.Sleep(100 * time.Millisecond)

	return nil
}

// Helper to check if DLL is loaded
func IsDLLLoaded() bool {
	dllMutex.RLock()
	defer dllMutex.RUnlock()
	return isDLLLoaded
}

// Add this helper function to check for admin privileges
func isAdmin() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}

// Option is a function that configures a WinDivertHandle
type Option func(*WinDivertHandleConfig)

// WinDivertHandleConfig holds configuration for WinDivertHandle
type WinDivertHandleConfig struct {
	layer    Layer
	priority int16
	flags    Flags
}

// WithLayer sets the layer for the WinDivertHandle
func WithLayer(layer Layer) Option {
	return func(cfg *WinDivertHandleConfig) {
		cfg.layer = layer
	}
}

// WithPriority sets the priority for the WinDivertHandle
func WithPriority(priority int16) Option {
	return func(cfg *WinDivertHandleConfig) {
		cfg.priority = priority
	}
}

// WithFlags sets the flags for the WinDivertHandle
func WithFlags(flags Flags) Option {
	return func(cfg *WinDivertHandleConfig) {
		cfg.flags = flags
	}
}

// NewWinDivertHandle creates a new WinDivertHandle with the given filter and options
func NewWinDivertHandle(filter string, opts ...Option) (*WinDivertHandle, error) {
	if !isDLLLoaded {
		return nil, errors.New("WinDivert DLL not loaded")
	}

	filterPtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, fmt.Errorf("invalid filter string: %v", err)
	}

	// Verify filter syntax first
	if ok, pos := HelperCompileFilter(filter); !ok {
		return nil, fmt.Errorf("invalid filter at position %d", pos)
	}

	// Default configuration
	cfg := &WinDivertHandleConfig{
		layer:    LayerNetwork,
		priority: 0,
		flags:    0,
	}

	// Apply options
	for _, opt := range opts {
		opt(cfg)
	}

	// Validate flags
	if !cfg.flags.IsValid() {
		return nil, errors.New("invalid flags combination")
	}

	// Validate layer-specific required flags
	switch cfg.layer {
	case LayerFlow:
		if !cfg.flags.Has(FlagSniff | FlagRecvOnly) {
			return nil, errors.New("flow layer requires FlagSniff and FlagRecvOnly")
		}
	case LayerSocket:
		if !cfg.flags.Has(FlagRecvOnly) {
			return nil, errors.New("socket layer requires FlagRecvOnly")
		}
	case LayerReflect:
		if !cfg.flags.Has(FlagSniff | FlagRecvOnly) {
			return nil, errors.New("reflect layer requires FlagSniff and FlagRecvOnly")
		}
	}

	// Open handle with detailed diagnostics
	handle, _, err := winDivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(cfg.layer),
		uintptr(cfg.priority),
		uintptr(cfg.flags))

	if handle == 0 {
		// Get detailed Windows error
		if errno, ok := err.(syscall.Errno); ok {
			switch errno {
			case 5:
				return nil, errors.New("access denied - are you running as Administrator?")
			case 577:
				return nil, errors.New("driver not installed or started - check Windows Event Log")
			case 87:
				return nil, errors.New("invalid parameter - filter syntax error")
			default:
				return nil, fmt.Errorf("WinDivertOpen failed: %v (errno: %d)", err, errno)
			}
		}
		return nil, fmt.Errorf("WinDivertOpen failed: %v", err)
	}

	winDivertHandle := &WinDivertHandle{
		handle: handle,
		open:   true,
	}

	runtime.SetFinalizer(winDivertHandle, func(h *WinDivertHandle) {
		h.Close()
	})

	return winDivertHandle, nil
}

// Close the Handle
// See https://reqrypt.org/windivert-doc.html#divert_close
func (wd *WinDivertHandle) Close() error {
	if !wd.open {
		return nil
	}

	// Check if DLL is loaded and proc is available
	dllMutex.RLock()
	if !isDLLLoaded || winDivertClose == nil {
		dllMutex.RUnlock()
		return errors.New("WinDivert DLL not loaded")
	}

	// Keep the lock until we're done with the proc
	ret, _, err := winDivertClose.Call(wd.handle)
	dllMutex.RUnlock()

	if ret == 0 { // WinDivert functions return 0 on failure
		return fmt.Errorf("WinDivertClose failed: %v", err)
	}

	wd.open = false
	wd.handle = 0 // Clear the handle
	return nil
}

// Recv receives a packet from the network stack
func (wd *WinDivertHandle) Recv() (*Packet, error) {
	if !wd.open {
		return nil, errors.New("can't receive, the handle isn't open")
	}

	if winDivertRecv == nil {
		return nil, errors.New("WinDivert DLL not loaded")
	}

	packetBuffer := GetBuffer(defaultBufferSize)
	defer PutBuffer(packetBuffer)

	var packetLen uint32
	var addr WinDivertAddress

	success, _, err := winDivertRecv.Call(
		wd.handle,
		uintptr(unsafe.Pointer(&packetBuffer[0])),
		uintptr(defaultBufferSize),
		uintptr(unsafe.Pointer(&packetLen)),
		uintptr(unsafe.Pointer(&addr)),
	)

	if success == 0 {
		return nil, fmt.Errorf("WinDivertRecv failed: %v", err)
	}

	if packetLen > uint32(defaultBufferSize) {
		return nil, fmt.Errorf("received packet length %d exceeds buffer size %d", packetLen, defaultBufferSize)
	}

	// Get a new buffer of exact size needed
	finalBuffer := GetBuffer(int(packetLen))
	copy(finalBuffer, packetBuffer[:packetLen])

	packet := &Packet{
		Raw:       finalBuffer,
		Addr:      &addr,
		PacketLen: uint(packetLen),
	}

	return packet, nil
}

// Send injects a packet into the network stack
func (wd *WinDivertHandle) Send(packet *Packet) (uint, error) {
	if !wd.open {
		return 0, fmt.Errorf("Send: handle not open")
	}

	if packet == nil {
		return 0, fmt.Errorf("Send: nil packet provided")
	}

	// Lock DLL access to prevent unloading while we're using it
	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertSend == nil || winDivertHelperCalcChecksums == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	// Initialize WinDivertAddress if not set
	if packet.Addr == nil {
		packet.Addr = &WinDivertAddress{}
	}

	// Calculate checksums before sending
	if err := wd.HelperCalcChecksum(packet); err != nil {
		// Log but don't fail on checksum errors
		log.Printf("Warning: Checksum calculation failed: %v\n", err)
	}

	var sendLen uint32
	success, _, err := winDivertSend.Call(
		wd.handle,
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(packet.Addr)))

	if success == 0 {
		return 0, fmt.Errorf("WinDivertSend failed: %v", err)
	}

	return uint(sendLen), nil
}

// Calls WinDivertHelperCalcChecksum to calculate the packet's checksum
func (wd *WinDivertHandle) HelperCalcChecksum(packet *Packet) error {
	if winDivertHelperCalcChecksums == nil {
		return errors.New("WinDivert DLL not loaded")
	}

	success, _, err := winDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(packet.Addr)),
		uintptr(0))

	if success == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums failed: %v", err)
	}
	return nil
}

// Take the given filter and check if it contains any error
// https://reqrypt.org/windivert-doc.html#divert_helper_check_filter
func HelperCompileFilter(filter string) (bool, int) {
	if !isDLLLoaded || winDivertHelperCompileFilter == nil {
		return false, 0
	}

	var errorStr *byte
	var errorPos uint

	filterBytePtr, _ := syscall.BytePtrFromString(filter)

	success, _, _ := winDivertHelperCompileFilter.Call(
		uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(LayerNetwork),
		0,
		0,
		uintptr(unsafe.Pointer(&errorStr)),
		uintptr(unsafe.Pointer(&errorPos)))

	if success == 1 {
		return true, -1
	}
	return false, int(errorPos)
}

// Take a packet and compare it with the given filter
// Returns true if the packet matches the filter
// https://reqrypt.org/windivert-doc.html#divert_helper_eval_filter
func HelperEvalFilter(packet *Packet, filter string) (bool, error) {
	filterBytePtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}

	success, _, err := winDivertHelperEvalFilter.Call(
		uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&packet.Addr)))

	if success == 0 {
		return false, err
	}

	return true, nil
}

// A loop that capture packets by calling Recv and sends them on a channel as long as the handle is open
// If Recv() returns an error, the loop is stopped and the channel is closed
func (wd *WinDivertHandle) recvLoop(packetChan chan<- *Packet) {
	for wd.open {
		packet, err := wd.Recv()
		if err != nil {
			//close(packetChan)
			break
		}

		packetChan <- packet
	}
}

// Create a new channel that will be used to pass captured packets and returns it calls recvLoop to maintain a loop
func (wd *WinDivertHandle) Packets(ctx context.Context) (<-chan *Packet, error) {
	if !wd.open {
		return nil, errors.New("the handle isn't open")
	}

	packetChan := make(chan *Packet, PacketChanCapacity)

	go func() {
		defer close(packetChan)

		for wd.open {
			select {
			case <-ctx.Done():
				return
			default:
				packet, err := wd.Recv()
				if err != nil {
					return
				}
				packetChan <- packet
			}
		}
	}()

	return packetChan, nil
}

// RecvEx receives a packet with extended options
func (wd *WinDivertHandle) RecvEx(packet []byte, addr *WinDivertAddress, flags uint64, overlapped *windows.Overlapped) (uint, error) {
	if !wd.open {
		return 0, errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertRecvEx == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	var recvLen uint32
	success, _, err := winDivertRecvEx.Call(
		wd.handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(flags),
		uintptr(unsafe.Pointer(addr)),
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if success == 0 {
		return 0, fmt.Errorf("WinDivertRecvEx failed: %v", err)
	}

	return uint(recvLen), nil
}

// SendEx sends a packet with extended options
func (wd *WinDivertHandle) SendEx(packet []byte, addr *WinDivertAddress, flags uint64, overlapped *windows.Overlapped) (uint, error) {
	if !wd.open {
		return 0, errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertSendEx == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	var sendLen uint32
	success, _, err := winDivertSendEx.Call(
		wd.handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(flags),
		uintptr(unsafe.Pointer(addr)),
		uintptr(unsafe.Pointer(overlapped)),
	)

	if success == 0 {
		return 0, fmt.Errorf("WinDivertSendEx failed: %v", err)
	}

	return uint(sendLen), nil
}

// Shutdown shuts down the handle
func (wd *WinDivertHandle) Shutdown(how uint) error {
	if !wd.open {
		return errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertShutdown == nil {
		return errors.New("WinDivert DLL not loaded")
	}

	success, _, err := winDivertShutdown.Call(
		wd.handle,
		uintptr(how),
	)

	if success == 0 {
		return fmt.Errorf("WinDivertShutdown failed: %v", err)
	}

	return nil
}

// SetParam sets a WinDivert parameter
func (wd *WinDivertHandle) SetParam(param uint, value uint64) error {
	if !wd.open {
		return errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertSetParam == nil {
		return errors.New("WinDivert DLL not loaded")
	}

	success, _, err := winDivertSetParam.Call(
		wd.handle,
		uintptr(param),
		uintptr(value),
	)

	if success == 0 {
		return fmt.Errorf("WinDivertSetParam failed: %v", err)
	}

	return nil
}

// GetParam gets a WinDivert parameter
func (wd *WinDivertHandle) GetParam(param uint) (uint64, error) {
	if !wd.open {
		return 0, errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertGetParam == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	var value uint64
	success, _, err := winDivertGetParam.Call(
		wd.handle,
		uintptr(param),
		uintptr(unsafe.Pointer(&value)),
	)

	if success == 0 {
		return 0, fmt.Errorf("WinDivertGetParam failed: %v", err)
	}

	return value, nil
}

// ParsedPacket represents a parsed network packet
type ParsedPacket struct {
	Raw    []byte
	IPv4   *header.IPv4Header
	IPv6   *header.IPv6Header
	ICMP   *header.ICMPv4Header
	ICMPv6 *header.ICMPv6Header
	TCP    *header.TCPHeader
	UDP    *header.UDPHeader
}

// HelperParsePacket parses a raw packet into its components
func HelperParsePacket(packet []byte) (*ParsedPacket, error) {
	if winDivertHelperParsePacket == nil {
		return nil, errors.New("WinDivert DLL not loaded")
	}

	var ipHdr, ipv6Hdr, icmpHdr, icmpv6Hdr, tcpHdr, udpHdr unsafe.Pointer
	var protocol uint8
	var data unsafe.Pointer
	var dataLen uint
	var next unsafe.Pointer
	var nextLen uint

	success, _, err := winDivertHelperParsePacket.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&ipHdr)),
		uintptr(unsafe.Pointer(&ipv6Hdr)),
		uintptr(unsafe.Pointer(&protocol)),
		uintptr(unsafe.Pointer(&icmpHdr)),
		uintptr(unsafe.Pointer(&icmpv6Hdr)),
		uintptr(unsafe.Pointer(&tcpHdr)),
		uintptr(unsafe.Pointer(&udpHdr)),
		uintptr(unsafe.Pointer(&data)),
		uintptr(unsafe.Pointer(&dataLen)),
		uintptr(unsafe.Pointer(&next)),
		uintptr(unsafe.Pointer(&nextLen)),
	)

	if success == 0 {
		return nil, fmt.Errorf("WinDivertHelperParsePacket failed: %v", err)
	}

	return &ParsedPacket{
		Raw:    packet,
		IPv4:   (*header.IPv4Header)(ipHdr),
		IPv6:   (*header.IPv6Header)(ipv6Hdr),
		ICMP:   (*header.ICMPv4Header)(icmpHdr),
		ICMPv6: (*header.ICMPv6Header)(icmpv6Hdr),
		TCP:    (*header.TCPHeader)(tcpHdr),
		UDP:    (*header.UDPHeader)(udpHdr),
	}, nil
}

// HelperHashPacket calculates a 64-bit hash of the packet
func HelperHashPacket(packet []byte, seed uint64) (uint64, error) {
	if winDivertHelperHashPacket == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	if len(packet) == 0 {
		return 0, errors.New("empty packet")
	}

	// Call WinDivertHelperHashPacket and get return value directly
	ret, _, err := winDivertHelperHashPacket.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(seed))

	// Windows syscalls often return an error even on success
	if err != nil && err != windows.ERROR_SUCCESS {
		return 0, fmt.Errorf("WinDivertHelperHashPacket failed: %v", err)
	}

	return uint64(ret), nil
}

// HelperParseIPv4Address parses an IPv4 address string
func HelperParseIPv4Address(addrStr string) (uint32, error) {
	if winDivertHelperParseIPv4Address == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	var addr uint32
	addrPtr, err := syscall.BytePtrFromString(addrStr)
	if err != nil {
		return 0, err
	}

	success, _, err := winDivertHelperParseIPv4Address.Call(
		uintptr(unsafe.Pointer(addrPtr)),
		uintptr(unsafe.Pointer(&addr)),
	)

	if success == 0 {
		return 0, fmt.Errorf("WinDivertHelperParseIPv4Address failed: %v", err)
	}

	return addr, nil
}

// HelperParseIPv6Address parses an IPv6 address string
func HelperParseIPv6Address(addrStr string) ([4]uint32, error) {
	if winDivertHelperParseIPv6Address == nil {
		return [4]uint32{}, errors.New("WinDivert DLL not loaded")
	}

	var addr [4]uint32
	addrPtr, err := syscall.BytePtrFromString(addrStr)
	if err != nil {
		return [4]uint32{}, err
	}

	success, _, err := winDivertHelperParseIPv6Address.Call(
		uintptr(unsafe.Pointer(addrPtr)),
		uintptr(unsafe.Pointer(&addr)),
	)

	if success == 0 {
		return [4]uint32{}, fmt.Errorf("WinDivertHelperParseIPv6Address failed: %v", err)
	}

	return addr, nil
}

// HelperFormatIPv4Address formats an IPv4 address as a string
func HelperFormatIPv4Address(addr uint32) (string, error) {
	if winDivertHelperFormatIPv4Address == nil {
		return "", errors.New("WinDivert DLL not loaded")
	}

	buf := make([]byte, 16)
	success, _, err := winDivertHelperFormatIPv4Address.Call(
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if success == 0 {
		return "", fmt.Errorf("WinDivertHelperFormatIPv4Address failed: %v", err)
	}

	return string(buf[:bytes.IndexByte(buf, 0)]), nil
}

// HelperFormatIPv6Address formats an IPv6 address as a string
func HelperFormatIPv6Address(addr [4]uint32) (string, error) {
	if winDivertHelperFormatIPv6Address == nil {
		return "", errors.New("WinDivert DLL not loaded")
	}

	buf := make([]byte, 46)
	success, _, err := winDivertHelperFormatIPv6Address.Call(
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)

	if success == 0 {
		return "", fmt.Errorf("WinDivertHelperFormatIPv6Address failed: %v", err)
	}

	return string(buf[:bytes.IndexByte(buf, 0)]), nil
}

// Byte order conversion helpers
func HelperNtohs(x uint16) uint16 {
	ret, _, _ := winDivertHelperNtohs.Call(uintptr(x))
	return uint16(ret)
}

func HelperNtohl(x uint32) uint32 {
	ret, _, _ := winDivertHelperNtohl.Call(uintptr(x))
	return uint32(ret)
}

func HelperNtohll(x uint64) uint64 {
	ret, _, _ := winDivertHelperNtohll.Call(uintptr(x))
	return uint64(ret)
}

func HelperHtons(x uint16) uint16 {
	ret, _, _ := winDivertHelperHtons.Call(uintptr(x))
	return uint16(ret)
}

func HelperHtonl(x uint32) uint32 {
	ret, _, _ := winDivertHelperHtonl.Call(uintptr(x))
	return uint32(ret)
}

func HelperHtonll(x uint64) uint64 {
	ret, _, _ := winDivertHelperHtonll.Call(uintptr(x))
	return uint64(ret)
}

func HelperNtohIPv6Address(inAddr [4]uint32) [4]uint32 {
	var outAddr [4]uint32
	winDivertHelperNtohIPv6Address.Call(
		uintptr(unsafe.Pointer(&inAddr)),
		uintptr(unsafe.Pointer(&outAddr)),
	)
	return outAddr
}

func HelperHtonIPv6Address(inAddr [4]uint32) [4]uint32 {
	var outAddr [4]uint32
	winDivertHelperHtonIPv6Address.Call(
		uintptr(unsafe.Pointer(&inAddr)),
		uintptr(unsafe.Pointer(&outAddr)),
	)
	return outAddr
}

// RecvBatch receives multiple packets in a single call for better performance
func (wd *WinDivertHandle) RecvBatch(maxPackets int) ([]*Packet, error) {
	if !wd.open {
		return nil, errors.New("handle not open")
	}

	dllMutex.RLock()
	defer dllMutex.RUnlock()

	if winDivertRecvEx == nil {
		return nil, errors.New("WinDivert DLL not loaded")
	}

	// Allocate buffers for batch receive
	packetBuffer := make([]byte, maxPackets*PacketBufferSize)
	addresses := make([]WinDivertAddress, maxPackets)
	var recvLen uint32
	addrLen := uint32(unsafe.Sizeof(WinDivertAddress{}) * uintptr(maxPackets))

	// Call WinDivertRecvEx with correct parameter order
	success, _, err := winDivertRecvEx.Call(
		wd.handle, // handle
		uintptr(unsafe.Pointer(&packetBuffer[0])), // pPacket
		uintptr(len(packetBuffer)),                // packetLen
		uintptr(unsafe.Pointer(&recvLen)),         // pRecvLen
		0,                                         // flags (must be 0)
		uintptr(unsafe.Pointer(&addresses[0])),    // pAddr
		uintptr(unsafe.Pointer(&addrLen)),         // pAddrLen
		0)                                         // lpOverlapped

	if success == 0 {
		if err == windows.ERROR_INSUFFICIENT_BUFFER {
			return nil, fmt.Errorf("buffer too small for batch receive")
		}
		return nil, fmt.Errorf("WinDivertRecvEx failed: %v", err)
	}

	// Calculate number of packets received
	numPackets := addrLen / uint32(unsafe.Sizeof(WinDivertAddress{}))

	// Process received packets
	packets := make([]*Packet, 0, numPackets)
	offset := uint32(0)

	// Calculate size per packet (total bytes divided by number of packets)
	packetSize := recvLen / numPackets

	for i := uint32(0); i < numPackets && offset < recvLen; i++ {
		// Get packet data
		var packetLen uint32
		if i == numPackets-1 {
			// Last packet gets all remaining bytes
			packetLen = recvLen - offset
		} else {
			packetLen = packetSize
		}

		// Validate packet length
		if packetLen == 0 || offset+packetLen > recvLen {
			continue
		}

		// Copy packet data
		packetData := make([]byte, packetLen)
		copy(packetData, packetBuffer[offset:offset+packetLen])

		// Create packet struct with copied address
		addrCopy := addresses[i]
		packets = append(packets, &Packet{
			Raw:       packetData,
			Addr:      &addrCopy,
			PacketLen: uint(packetLen),
		})

		// Move to next packet
		offset += packetLen
	}

	return packets, nil
}
