//go:build windows
// +build windows

package godivert

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func setupTestDLL(t *testing.T) {
	t.Helper()
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload initial DLL: %v", err)
	}
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}
}

func TestDLLLifecycle(t *testing.T) {
	// Ensure clean initial state by unloading any existing DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload initial DLL: %v", err)
	}

	// Verify initial state
	if IsDLLLoaded() {
		t.Fatal("DLL should not be loaded initially")
	}

	// Test loading
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	if !IsDLLLoaded() {
		t.Fatal("DLL should be loaded after LoadDLL")
	}

	// Verify procs are initialized
	if winDivertOpen == nil || winDivertClose == nil {
		t.Fatal("DLL procs not properly initialized")
	}

	// Test double loading (should be no-op)
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Second LoadDLL failed: %v", err)
	}

	// Test unloading
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload DLL: %v", err)
	}

	if IsDLLLoaded() {
		t.Fatal("DLL should not be loaded after UnloadDLL")
	}

	// Verify procs are nil
	if winDivertOpen != nil || winDivertClose != nil {
		t.Fatal("DLL procs not properly cleared")
	}
}

func TestDLLFinalization(t *testing.T) {
	// First unload any existing DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload initial DLL: %v", err)
	}

	// Load DLL
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	// Create a handle to ensure DLL is in use
	handle, err := NewWinDivertHandle("false")
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}

	// Close handle explicitly
	if err := handle.Close(); err != nil {
		t.Fatalf("Failed to close handle: %v", err)
	}

	// Unload DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload DLL: %v", err)
	}

	// Verify DLL is unloaded
	if IsDLLLoaded() {
		t.Fatal("DLL should be unloaded")
	}

	// Verify procs are nil
	if winDivertOpen != nil || winDivertClose != nil {
		t.Fatal("DLL procs not properly cleared")
	}

	// Try to create a new handle - should fail
	if _, err := NewWinDivertHandle("false"); err == nil {
		t.Fatal("Should not be able to create handle after DLL unload")
	}
}

func TestConcurrentAccess(t *testing.T) {
	const goroutines = 10
	errChan := make(chan error, goroutines*2)
	done := make(chan bool)

	// Spawn multiple goroutines trying to load/unload simultaneously
	for i := 0; i < goroutines; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
						errChan <- err
						return
					}
					if err := UnloadDLL(); err != nil {
						errChan <- err
						return
					}
				}
			}
		}()
	}

	// Let it run for a bit
	time.Sleep(2 * time.Second)
	close(done)

	// Check for any errors
	close(errChan)
	for err := range errChan {
		t.Errorf("Concurrent operation failed: %v", err)
	}
}

func TestDLLUnloadAndRemoval(t *testing.T) {
	if !isAdmin() {
		t.Skip("Test requires administrator privileges")
	}

	// First unload any existing DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload existing DLL: %v", err)
	}

	// Create temp directory for test files
	tmpDir, err := os.MkdirTemp("", "windivert_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Handle DLL, SYS and LIB files
	dllPath := filepath.Join(tmpDir, "WinDivert.dll")
	sysPath := filepath.Join(tmpDir, "WinDivert64.sys")
	libPath := filepath.Join(tmpDir, "WinDivert.lib")

	// Copy source files to temp location
	files := map[string]string{
		"WinDivert.dll":   dllPath,
		"WinDivert64.sys": sysPath,
		"WinDivert.lib":   libPath,
	}

	// Copy all files
	for src, dst := range files {
		srcData, err := os.ReadFile(src)
		if err != nil {
			t.Skipf("Test requires %s in current directory: %v", src, err)
		}
		if err := os.WriteFile(dst, srcData, 0755); err != nil {
			t.Fatalf("Failed to write %s: %v", src, err)
		}
	}

	// Load DLL from temp location
	if err := LoadDLL(dllPath, dllPath); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	// Create and use a handle to ensure driver is loaded
	handle, err := NewWinDivertHandle("true")
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}

	// Make sure to close handle before unloading
	if err := handle.Close(); err != nil {
		t.Fatalf("Failed to close handle: %v", err)
	}

	// Unload DLL and wait for Windows to release handles
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload DLL: %v", err)
	}

	// Give more time for driver unload
	time.Sleep(2 * time.Second)

	// Try to remove files with retries
	filesToRemove := []string{sysPath, libPath}
	for _, file := range filesToRemove {
		var removeErr error
		for i := 0; i < 5; i++ {
			removeErr = os.Remove(file)
			if removeErr == nil {
				break
			}
			time.Sleep(time.Second)
		}
		if removeErr != nil {
			t.Errorf("Failed to remove %s after %d attempts: %v", filepath.Base(file), 5, removeErr)
		}
	}
}

func TestNewWinDivertHandlePrivileges(t *testing.T) {
	if !isAdmin() {
		t.Skip("Test requires administrator privileges")
	}

	// Ensure DLL is loaded first
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	handle, err := NewWinDivertHandle("true")
	if err != nil {
		t.Fatalf("Failed to create handle with admin rights: %v", err)
	}
	defer handle.Close()

	if !handle.open {
		t.Error("Handle should be open")
	}
}

func createICMPPacket() []byte {
	// Create an ICMP echo request packet with:
	// - 20 bytes IPv4 header
	// - 8 bytes ICMP header
	// - 56 bytes payload (standard ping size)
	packet := make([]byte, 84)

	// IPv4 header fields
	packet[0] = 0x45                                    // Version 4, IHL 5 (20 bytes)
	packet[1] = 0x00                                    // DSCP & ECN
	binary.BigEndian.PutUint16(packet[2:4], uint16(84)) // Total length
	packet[8] = 64                                      // TTL
	packet[9] = 0x01                                    // Protocol (1 = ICMP)

	// Source IP (192.168.1.1)
	copy(packet[12:16], net.ParseIP("192.168.1.1").To4())
	// Destination IP (192.168.1.2)
	copy(packet[16:20], net.ParseIP("192.168.1.2").To4())

	// ICMP header (8 bytes)
	packet[20] = 0x08 // Type (echo request)
	packet[21] = 0x00 // Code
	// Identifier and sequence will be at 24-28

	// Payload (56 bytes of dummy data)
	for i := 28; i < 84; i++ {
		packet[i] = byte(i - 28)
	}

	return packet
}

func calculateChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func TestWinDivertBasicOperations(t *testing.T) {
	if !isAdmin() {
		t.Skip("Test requires administrator privileges")
	}

	// Load DLL
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	// Verify DLL is loaded
	if !IsDLLLoaded() {
		t.Fatal("DLL should be loaded")
	}

	// Open a handle with a basic filter and specific layer/flags
	handle, err := NewWinDivertHandle("icmp",
		WithLayer(LayerNetwork),
		WithFlags(FlagSniff))
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}
	defer handle.Close()

	// Verify handle is open
	if !handle.open {
		t.Error("Handle should be open")
	}

	// Test sending an ICMP packet
	icmpPacket := createICMPPacket()
	fmt.Printf("Test - ICMP packet length: %d\n", len(icmpPacket))
	fmt.Printf("Test - ICMP packet content: %v\n", icmpPacket)

	addr := &WinDivertAddress{}
	addr.SetLayer(uint8(LayerNetwork)) // Convert Layer to uint8
	addr.SetFlags(0)
	fmt.Printf("Test - WinDivertAddress: %+v\n", addr)

	dummyPacket := &Packet{
		Raw:       icmpPacket,
		Addr:      addr,
		PacketLen: uint(len(icmpPacket)),
	}

	fmt.Printf("Test - Before Send:\n")
	fmt.Printf("  PacketLen: %d\n", dummyPacket.PacketLen)
	fmt.Printf("  Raw length: %d\n", len(dummyPacket.Raw))
	fmt.Printf("  Addr: %+v\n", dummyPacket.Addr)

	sentLen, err := handle.Send(dummyPacket)
	fmt.Printf("Test - After Send:\n")
	fmt.Printf("  Error: %v\n", err)
	fmt.Printf("  SentLen: %d\n", sentLen)

	if err != nil {
		t.Errorf("Failed to send packet: %v", err)
	}
	if sentLen != dummyPacket.PacketLen {
		t.Errorf("Sent length mismatch: expected %d, got %d", dummyPacket.PacketLen, sentLen)
	}

	// Unload DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload DLL: %v", err)
	}
}

func TestWinDivertSendReceive(t *testing.T) {
	if !isAdmin() {
		t.Skip("Test requires administrator privileges")
	}

	setupTestDLL(t)
	defer UnloadDLL()

	// Open a handle with specific options
	handle, err := NewWinDivertHandle("true",
		WithLayer(LayerNetwork),
		WithPriority(0),
		WithFlags(0))
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}
	defer handle.Close()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a channel to receive packets
	packetChan, err := handle.Packets(ctx)
	if err != nil {
		t.Fatalf("Failed to create packet channel: %v", err)
	}

	// Simulate sending a packet
	go func() {
		// Create a proper ICMP packet instead of random bytes
		packet := createICMPPacket()

		// Create WinDivertAddress with proper direction and layer
		addr := &WinDivertAddress{}
		addr.SetLayer(uint8(LayerNetwork)) // Convert Layer to uint8
		addr.SetFlags(uint8(0))            // Clear flags first
		if WinDivertDirectionOutbound {
			addr.SetFlags(1) // Set outbound flag
		}

		dummyPacket := &Packet{
			Raw:       packet,
			Addr:      addr,
			PacketLen: uint(len(packet)),
		}

		// Calculate checksums before sending
		if err := handle.HelperCalcChecksum(dummyPacket); err != nil {
			t.Errorf("Failed to calculate checksums: %v", err)
			return
		}

		sentLen, err := handle.Send(dummyPacket)
		if err != nil {
			t.Errorf("Failed to send packet: %v", err)
			return
		}
		if sentLen != dummyPacket.PacketLen {
			t.Errorf("Sent length mismatch: expected %d, got %d", dummyPacket.PacketLen, sentLen)
			return
		}
		t.Logf("Successfully sent packet of length %d", sentLen)
	}()

	// Attempt to receive a packet
	select {
	case packet := <-packetChan:
		if len(packet.Raw) == 0 {
			t.Error("Received packet is empty")
		} else {
			parsed, err := HelperParsePacket(packet.Raw)
			if err != nil {
				t.Errorf("Failed to parse received packet: %v", err)
			} else {
				t.Logf("Received valid packet: IPv4=%v, ICMP=%v", parsed.IPv4 != nil, parsed.ICMP != nil)
			}
		}
	case <-time.After(5 * time.Second):
		t.Error("Timeout waiting for packet")
	}
}

func TestHelperCompileFilter(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	if winDivertHelperCompileFilter == nil {
		t.Fatal("WinDivertHelperCompileFilter proc is nil")
	}

	tests := []struct {
		name    string
		filter  string
		wantOk  bool
		wantPos int
	}{
		{
			name:    "valid filter",
			filter:  "true",
			wantOk:  true,
			wantPos: -1,
		},
		{
			name:    "valid complex filter",
			filter:  "tcp.DstPort == 80 and ip",
			wantOk:  true,
			wantPos: -1,
		},
		{
			name:    "invalid filter",
			filter:  "invalid",
			wantOk:  false,
			wantPos: 0,
		},
		{
			name:    "syntax error filter",
			filter:  "tcp.DstPort == &&",
			wantOk:  false,
			wantPos: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOk, gotPos := HelperCompileFilter(tt.filter)
			if gotOk != tt.wantOk || (tt.wantOk && gotPos != tt.wantPos) {
				t.Errorf("HelperCompileFilter() = %v, %v, want %v, %v",
					gotOk, gotPos, tt.wantOk, tt.wantPos)
			}
		})
	}
}

func TestHelperParsePacket(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	packet := createICMPPacket()
	parsed, err := HelperParsePacket(packet)
	if err != nil {
		t.Fatalf("HelperParsePacket failed: %v", err)
	}

	// Verify parsed packet components
	if parsed.IPv4 == nil {
		t.Error("Expected IPv4 header but got nil")
	}
	if parsed.ICMP == nil {
		t.Error("Expected ICMP header but got nil")
	}
}

func TestHelperHashPacket(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	packet := createICMPPacket()
	t.Logf("Test packet length: %d", len(packet))
	t.Logf("Test packet content: %x", packet)

	// Test with same seed should produce same hash
	hash1, err := HelperHashPacket(packet, 0)
	if err != nil {
		t.Fatalf("First HelperHashPacket failed: %v", err)
	}
	t.Logf("Hash1 (seed 0): %x", hash1)

	hash2, err := HelperHashPacket(packet, 0)
	if err != nil {
		t.Fatalf("Second HelperHashPacket failed: %v", err)
	}
	t.Logf("Hash2 (seed 0): %x", hash2)

	if hash1 != hash2 {
		t.Errorf("Same packet and seed produced different hashes: %x != %x", hash1, hash2)
	}

	// Test with different seeds should produce different hashes
	hash3, err := HelperHashPacket(packet, 1)
	if err != nil {
		t.Fatalf("Third HelperHashPacket failed: %v", err)
	}
	t.Logf("Hash3 (seed 1): %x", hash3)

	if hash1 == hash3 {
		t.Errorf("Different seeds produced same hash: %x", hash1)
	}

	// Test with different packets should produce different hashes
	modifiedPacket := make([]byte, len(packet))
	copy(modifiedPacket, packet)
	modifiedPacket[20] = modifiedPacket[20] + 1 // Modify ICMP type
	t.Logf("Modified packet content: %x", modifiedPacket)

	hash4, err := HelperHashPacket(modifiedPacket, 0)
	if err != nil {
		t.Fatalf("Fourth HelperHashPacket failed: %v", err)
	}
	t.Logf("Hash4 (modified packet, seed 0): %x", hash4)

	if hash1 == hash4 {
		t.Errorf("Different packets produced same hash: %x", hash1)
	}
}

func TestHelperIPv4AddressParsing(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"192.168.1.1", false},
		{"256.256.256.256", true},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr, err := HelperParseIPv4Address(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("HelperParseIPv4Address(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Try formatting it back
				formatted, err := HelperFormatIPv4Address(addr)
				if err != nil {
					t.Errorf("HelperFormatIPv4Address failed: %v", err)
				}
				if formatted != tt.addr {
					t.Errorf("Address roundtrip failed: got %v, want %v", formatted, tt.addr)
				}
			}
		})
	}
}

func TestHelperIPv6AddressParsing(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	tests := []struct {
		addr    string
		wantErr bool
	}{
		{"2001:db8::1", false},
		{"::1", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			addr, err := HelperParseIPv6Address(tt.addr)
			if (err != nil) != tt.wantErr {
				t.Errorf("HelperParseIPv6Address(%q) error = %v, wantErr %v", tt.addr, err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Try formatting it back
				formatted, err := HelperFormatIPv6Address(addr)
				if err != nil {
					t.Errorf("HelperFormatIPv6Address failed: %v", err)
				}
				if formatted != tt.addr {
					t.Errorf("Address roundtrip failed: got %v, want %v", formatted, tt.addr)
				}
			}
		})
	}
}

func TestHelperByteOrderConversion(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	// Test 16-bit conversions
	original16 := uint16(0x1234)
	network16 := HelperHtons(original16)
	if network16 == original16 {
		t.Error("HelperHtons did not change byte order")
	}
	host16 := HelperNtohs(network16)
	if host16 != original16 {
		t.Errorf("16-bit conversion roundtrip failed: got %x, want %x", host16, original16)
	}

	// Test 32-bit conversions
	original32 := uint32(0x12345678)
	network32 := HelperHtonl(original32)
	if network32 == original32 {
		t.Error("HelperHtonl did not change byte order")
	}
	host32 := HelperNtohl(network32)
	if host32 != original32 {
		t.Errorf("32-bit conversion roundtrip failed: got %x, want %x", host32, original32)
	}

	// Test 64-bit conversions
	original64 := uint64(0x1234567890ABCDEF)
	network64 := HelperHtonll(original64)
	if network64 == original64 {
		t.Error("HelperHtonll did not change byte order")
	}
	host64 := HelperNtohll(network64)
	if host64 != original64 {
		t.Errorf("64-bit conversion roundtrip failed: got %x, want %x", host64, original64)
	}
}

func TestHelperIPv6AddressConversion(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	original := [4]uint32{0x12345678, 0x9ABCDEF0, 0x11223344, 0x55667788}
	network := HelperHtonIPv6Address(original)
	if network == original {
		t.Error("HelperHtonIPv6Address did not change byte order")
	}
	host := HelperNtohIPv6Address(network)
	if host != original {
		t.Errorf("IPv6 address conversion roundtrip failed: got %v, want %v", host, original)
	}
}

func TestWinDivertFlags(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	tests := []struct {
		name    string
		flags   Flags
		wantErr bool
	}{
		{
			name:    "valid flags - sniff only",
			flags:   FlagSniff,
			wantErr: false,
		},
		{
			name:    "valid flags - drop only",
			flags:   FlagDrop,
			wantErr: false,
		},
		{
			name:    "invalid flags - sniff and drop",
			flags:   FlagSniff | FlagDrop,
			wantErr: true,
		},
		{
			name:    "invalid flags - recv and send only",
			flags:   FlagRecvOnly | FlagSendOnly,
			wantErr: true,
		},
		{
			name:    "valid flags - multiple compatible",
			flags:   FlagSniff | FlagFragments,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWinDivertHandle("true",
				WithLayer(LayerNetwork),
				WithFlags(tt.flags))

			if (err != nil) != tt.wantErr {
				t.Errorf("NewWinDivertHandle() with flags %v error = %v, wantErr %v",
					tt.flags, err, tt.wantErr)
			}
		})
	}
}

func TestWinDivertLayerFlags(t *testing.T) {
	setupTestDLL(t)
	defer UnloadDLL()

	tests := []struct {
		name    string
		layer   Layer
		flags   Flags
		wantErr bool
	}{
		{
			name:    "network layer - no required flags",
			layer:   LayerNetwork,
			flags:   0,
			wantErr: false,
		},
		{
			name:    "flow layer - correct flags",
			layer:   LayerFlow,
			flags:   FlagSniff | FlagRecvOnly,
			wantErr: false,
		},
		{
			name:    "flow layer - missing flags",
			layer:   LayerFlow,
			flags:   FlagSniff, // Missing FlagRecvOnly
			wantErr: true,
		},
		{
			name:    "socket layer - correct flags",
			layer:   LayerSocket,
			flags:   FlagRecvOnly,
			wantErr: false,
		},
		{
			name:    "socket layer - missing flags",
			layer:   LayerSocket,
			flags:   0,
			wantErr: true,
		},
		{
			name:    "reflect layer - correct flags",
			layer:   LayerReflect,
			flags:   FlagSniff | FlagRecvOnly,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewWinDivertHandle("true",
				WithLayer(tt.layer),
				WithFlags(tt.flags))

			if (err != nil) != tt.wantErr {
				t.Errorf("NewWinDivertHandle() with layer %v and flags %v error = %v, wantErr %v",
					tt.layer, tt.flags, err, tt.wantErr)
			}
		})
	}
}
