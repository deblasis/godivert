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
