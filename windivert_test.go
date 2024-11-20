//go:build windows
// +build windows

package godivert

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDLLLifecycle(t *testing.T) {
	// First unload any existing DLL
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
	// Load DLL
	if err := LoadDLL("WinDivert.dll", "WinDivert.dll"); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	// Store initial state
	initialHandle := winDivertDLL

	// Force garbage collection
	runtime.GC()
	time.Sleep(time.Second) // Give finalizer time to run

	// Verify DLL was unloaded by finalizer
	if winDivertDLL == initialHandle {
		t.Fatal("DLL not unloaded by finalizer")
	}

	if IsDLLLoaded() {
		t.Fatal("DLL should be unloaded after finalization")
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
	// First unload any existing DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload existing DLL: %v", err)
	}

	// Create temp directory for test DLLs
	tmpDir, err := os.MkdirTemp("", "windivert_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Copy DLL files to temp location
	dll64Path := filepath.Join(tmpDir, "WinDivert64.dll")
	dll32Path := filepath.Join(tmpDir, "WinDivert32.dll")

	// Copy your DLL files to temp location
	// ... copy logic here ...

	// Load DLL from temp location
	if err := LoadDLL(dll64Path, dll32Path); err != nil {
		t.Fatalf("Failed to load DLL: %v", err)
	}

	// Verify DLL is loaded
	if !IsDLLLoaded() {
		t.Fatal("DLL should be loaded")
	}

	// Create and use a handle to ensure DLL is actually loaded
	handle, err := NewWinDivertHandle("true")
	if err != nil {
		t.Fatalf("Failed to create handle: %v", err)
	}
	handle.Close()

	// Unload DLL
	if err := UnloadDLL(); err != nil {
		t.Fatalf("Failed to unload DLL: %v", err)
	}

	// Verify DLL is unloaded
	if IsDLLLoaded() {
		t.Fatal("DLL should be unloaded")
	}

	// Try to remove the DLL files
	time.Sleep(100 * time.Millisecond) // Give Windows time to release file handles

	err = os.Remove(dll64Path)
	if err != nil {
		t.Errorf("Failed to remove 64-bit DLL: %v", err)
	}

	err = os.Remove(dll32Path)
	if err != nil {
		t.Errorf("Failed to remove 32-bit DLL: %v", err)
	}
}
