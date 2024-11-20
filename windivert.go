package godivert

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winDivertDLL *windows.LazyDLL

	winDivertOpen                *windows.LazyProc
	winDivertClose               *windows.LazyProc
	winDivertRecv                *windows.LazyProc
	winDivertSend                *windows.LazyProc
	winDivertHelperCalcChecksums *windows.LazyProc
	winDivertHelperEvalFilter    *windows.LazyProc
	winDivertHelperCheckFilter   *windows.LazyProc

	// Track if DLL is loaded
	isDLLLoaded bool

	// Protect DLL loading/unloading operations
	dllMutex sync.RWMutex
)

func init() {
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		// Handle initialization error
		panic(err)
	}
}

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
		return nil // Already loaded
	}

	var dllPath string
	if runtime.GOARCH == "amd64" {
		dllPath = path64
	} else {
		dllPath = path32
	}

	// Load DLL
	winDivertDLL = windows.NewLazyDLL(dllPath)

	// Initialize proc addresses
	winDivertOpen = winDivertDLL.NewProc("WinDivertOpen")
	winDivertClose = winDivertDLL.NewProc("WinDivertClose")
	winDivertRecv = winDivertDLL.NewProc("WinDivertRecv")
	winDivertSend = winDivertDLL.NewProc("WinDivertSend")
	winDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")
	winDivertHelperEvalFilter = winDivertDLL.NewProc("WinDivertHelperEvalFilter")
	winDivertHelperCheckFilter = winDivertDLL.NewProc("WinDivertHelperCheckFilter")

	isDLLLoaded = true

	// Register cleanup on program exit
	runtime.SetFinalizer(winDivertDLL, func(dll *windows.LazyDLL) {
		UnloadDLL()
	})

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
	winDivertSend = nil
	winDivertHelperCalcChecksums = nil
	winDivertHelperEvalFilter = nil
	winDivertHelperCheckFilter = nil

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

// Modify NewWinDivertHandle to check for admin rights
func NewWinDivertHandle(filter string) (*WinDivertHandle, error) {
	if !isAdmin() {
		return nil, fmt.Errorf("administrator privileges required to create WinDivert handle")
	}
	return NewWinDivertHandleWithFlags(filter, 0)
}

// Also modify NewWinDivertHandleWithFlags
func NewWinDivertHandleWithFlags(filter string, flags uint8) (*WinDivertHandle, error) {
	if !isAdmin() {
		return nil, fmt.Errorf("administrator privileges required to create WinDivert handle")
	}

	filterBytePtr, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	handle, _, err := winDivertOpen.Call(uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(0),
		uintptr(flags))

	if handle == uintptr(syscall.InvalidHandle) {
		return nil, err
	}

	winDivertHandle := &WinDivertHandle{
		handle: handle,
		open:   true,
	}
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

// Divert a packet from the Network Stack
// https://reqrypt.org/windivert-doc.html#divert_recv
func (wd *WinDivertHandle) Recv() (*Packet, error) {
	if !wd.open {
		return nil, errors.New("can't receive, the handle isn't open")
	}

	if winDivertRecv == nil {
		return nil, errors.New("WinDivert DLL not loaded")
	}

	packetBuffer := make([]byte, PacketBufferSize)
	var packetLen uint
	var addr WinDivertAddress

	success, _, err := winDivertRecv.Call(wd.handle,
		uintptr(unsafe.Pointer(&packetBuffer[0])),
		uintptr(PacketBufferSize),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&packetLen)))

	if success == 0 {
		return nil, err
	}

	packet := &Packet{
		Raw:       packetBuffer[:packetLen],
		Addr:      &addr,
		PacketLen: packetLen,
	}

	return packet, nil
}

// Inject the packet on the Network Stack
// https://reqrypt.org/windivert-doc.html#divert_send
func (wd *WinDivertHandle) Send(packet *Packet) (uint, error) {
	if !wd.open {
		return 0, errors.New("can't Send, the handle isn't open")
	}

	if winDivertSend == nil {
		return 0, errors.New("WinDivert DLL not loaded")
	}

	var sendLen uint
	success, _, err := winDivertSend.Call(wd.handle,
		uintptr(unsafe.Pointer(&(packet.Raw[0]))),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(packet.Addr)),
		uintptr(unsafe.Pointer(&sendLen)))

	if success == 0 {
		return 0, err
	}

	return sendLen, nil
}

// Calls WinDivertHelperCalcChecksum to calculate the packet's chacksum
// https://reqrypt.org/windivert-doc.html#divert_helper_calc_checksums
func (wd *WinDivertHandle) HelperCalcChecksum(packet *Packet) {
	winDivertHelperCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet.Raw[0])),
		uintptr(packet.PacketLen),
		uintptr(unsafe.Pointer(&packet.Addr)),
		uintptr(0))
}

// Take the given filter and check if it contains any error
// https://reqrypt.org/windivert-doc.html#divert_helper_check_filter
func HelperCheckFilter(filter string) (bool, int) {
	var errorPos uint

	filterBytePtr, _ := syscall.BytePtrFromString(filter)

	success, _, _ := winDivertHelperCheckFilter.Call(
		uintptr(unsafe.Pointer(filterBytePtr)),
		uintptr(0),
		uintptr(0), // Not implemented yet
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
func (wd *WinDivertHandle) Packets() (chan *Packet, error) {
	if !wd.open {
		return nil, errors.New("the handle isn't open")
	}
	packetChan := make(chan *Packet, PacketChanCapacity)
	go wd.recvLoop(packetChan)
	return packetChan, nil
}
