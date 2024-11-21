package godivert

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"testing"
	"time"
)

// BenchmarkSuite runs all benchmarks and saves results
func BenchmarkSuite(b *testing.B) {
	resultsFile := fmt.Sprintf("bench_%s_%s_%s.txt",
		runtime.GOOS,
		runtime.GOARCH,
		time.Now().Format("20060102_150405"))

	f, err := os.Create(resultsFile)
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()

	// Write system info header
	fmt.Fprintf(f, "# GoOS: %s\n", runtime.GOOS)
	fmt.Fprintf(f, "# GOARCH: %s\n", runtime.GOARCH)
	fmt.Fprintf(f, "# CPU: %d\n", runtime.NumCPU())
	fmt.Fprintf(f, "# Go version: %s\n", runtime.Version())
	fmt.Fprintf(f, "# \n")
	fmt.Fprintf(f, "# Benchmark results:\n")

	// Capture benchmark output
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old }()

	// Run all benchmarks
	runPacketParsingBenchmarks(b)
	runPacketMarshalUnmarshalBenchmarks(b)
	runPacketHeaderAccessBenchmarks(b)
	runPacketModificationBenchmarks(b)
	runPacketAllocationBenchmarks(b)
}

func runPacketParsingBenchmarks(b *testing.B) {
	packets := []struct {
		name string
		raw  []byte
	}{
		{
			name: "IPv4_TCP_Small",
			raw: []byte{
				0x45, 0x00, 0x00, 0x28,
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
				0x00, 0x50, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x50, 0x02, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "IPv4_TCP_Large",
			raw: append([]byte{
				0x45, 0x00, 0x05, 0xdc,
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
			}, bytes.Repeat([]byte("X"), 1400)...),
		},
		{
			name: "IPv6_TCP",
			raw: append([]byte{
				0x60, 0x00, 0x00, 0x00,
				0x00, 0x14, 0x06, 0x40,
			}, append(
				net.ParseIP("2001:db8::1").To16(),
				net.ParseIP("2001:db8::2").To16()...,
			)...),
		},
	}

	b.Run("PacketParsing", func(b *testing.B) {
		for _, p := range packets {
			b.Run(p.name, func(b *testing.B) {
				packet := &Packet{
					Raw:       p.raw,
					PacketLen: uint(len(p.raw)),
					Addr:      NewWinDivertAddress(),
				}
				b.ResetTimer()
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					packet.parsed = false
					packet.ParseHeaders()
				}
			})
		}
	})
}

func runPacketMarshalUnmarshalBenchmarks(b *testing.B) {
	sizes := []int{64, 512, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Marshal/Unmarshal_%d", size), func(b *testing.B) {
			packet := &Packet{
				Raw:       make([]byte, size),
				PacketLen: uint(size),
				Addr:      NewWinDivertAddress(),
			}
			packet.Raw[0] = 0x45 // IPv4 header
			packet.ParseHeaders()

			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				data, err := packet.MarshalBinary()
				if err != nil {
					b.Fatal(err)
				}
				restored := &Packet{}
				if err := restored.UnmarshalBinary(data); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func runPacketHeaderAccessBenchmarks(b *testing.B) {
	packet := &Packet{
		Raw: []byte{
			0x45, 0x00, 0x00, 0x28,
			0x00, 0x00, 0x40, 0x00,
			0x40, 0x06, 0x00, 0x00,
			0x0a, 0x00, 0x00, 0x01,
			0x0a, 0x00, 0x00, 0x02,
			0x00, 0x50, 0x20, 0x00,
		},
		PacketLen: 40,
		Addr:      NewWinDivertAddress(),
	}
	packet.ParseHeaders()

	b.Run("HeaderAccess", func(b *testing.B) {
		b.Run("SrcIP", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = packet.SrcIP()
			}
		})

		b.Run("DstIP", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = packet.DstIP()
			}
		})

		b.Run("SrcPort", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = packet.SrcPort()
			}
		})
	})
}

func runPacketModificationBenchmarks(b *testing.B) {
	packet := &Packet{
		Raw: []byte{
			0x45, 0x00, 0x00, 0x28,
			0x00, 0x00, 0x40, 0x00,
			0x40, 0x06, 0x00, 0x00,
			0x0a, 0x00, 0x00, 0x01,
			0x0a, 0x00, 0x00, 0x02,
			0x00, 0x50, 0x20, 0x00,
		},
		PacketLen: 40,
		Addr:      NewWinDivertAddress(),
	}
	packet.ParseHeaders()
	newIP := net.ParseIP("192.168.1.1")

	b.Run("Modification", func(b *testing.B) {
		b.Run("SetSrcIP", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				packet.SetSrcIP(newIP)
			}
		})

		b.Run("SetDstIP", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				packet.SetDstIP(newIP)
			}
		})

		b.Run("SetSrcPort", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = packet.SetSrcPort(8080)
			}
		})
	})
}

func runPacketAllocationBenchmarks(b *testing.B) {
	sizes := []int{64, 512, 1500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("Allocation_%d", size), func(b *testing.B) {
			// Create a valid IPv4 packet template
			template := make([]byte, size)
			// Set IPv4 version and header length (0x45 = version 4, header length 5 DWORDs)
			template[0] = 0x45
			// Set total length
			binary.BigEndian.PutUint16(template[2:4], uint16(size))
			// Set protocol (TCP)
			template[9] = 0x06
			// Add some IP addresses
			copy(template[12:16], net.ParseIP("192.168.1.1").To4())
			copy(template[16:20], net.ParseIP("192.168.1.2").To4())

			// Add TCP header if there's enough space
			if size >= 40 {
				// Source port (1234)
				binary.BigEndian.PutUint16(template[20:22], 1234)
				// Destination port (80)
				binary.BigEndian.PutUint16(template[22:24], 80)
				// Sequence number
				binary.BigEndian.PutUint32(template[24:28], 12345)
				// Acknowledgment number
				binary.BigEndian.PutUint32(template[28:32], 0)
				// Data offset and flags
				template[32] = 0x50 // 5 DWORDs, no flags
				template[33] = 0x02 // SYN flag
				// Window size
				binary.BigEndian.PutUint16(template[34:36], 8192)
			}

			// Fill rest with random data
			if size > 40 {
				rand.Read(template[40:])
			}

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				packet := &Packet{
					Raw:       make([]byte, size),
					PacketLen: uint(size),
					Addr:      NewWinDivertAddress(),
				}
				copy(packet.Raw, template)
				packet.ParseHeaders()
			}
		})
	}
}
