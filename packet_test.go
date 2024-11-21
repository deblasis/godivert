package godivert

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"testing/quick"

	"github.com/deblasis/godivert/header"
)

func TestPacketMarshalUnmarshalVariousTypes(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		len  uint
	}{
		{
			name: "IPv4 TCP",
			raw: []byte{
				0x45, 0x00, 0x00, 0x28, // IPv4 header
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01, // Source IP
				0x0a, 0x00, 0x00, 0x02, // Destination IP
				0x00, 0x50, 0x20, 0x00, // TCP header (port 80, 8192)
				0x00, 0x00, 0x00, 0x00,
				0x50, 0x02, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			len: 32,
		},
		{
			name: "IPv4 UDP",
			raw: []byte{
				0x45, 0x00, 0x00, 0x1c, // IPv4 header
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x11, 0x00, 0x00, // UDP protocol
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
				0x00, 0x35, 0x20, 0x00, // UDP header (port 53, 8192)
				0x00, 0x08, 0x00, 0x00, // Length and checksum
			},
			len: 28,
		},
		{
			name: "IPv4 ICMP",
			raw: []byte{
				0x45, 0x00, 0x00, 0x1c, // IPv4 header
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x01, 0x00, 0x00, // ICMP protocol
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
				0x08, 0x00, 0x00, 0x00, // ICMP header (echo request)
				0x00, 0x00, 0x00, 0x00,
			},
			len: 28,
		},
		{
			name: "IPv6 TCP",
			raw: append([]byte{
				0x60, 0x00, 0x00, 0x00, // IPv6 header
				0x00, 0x14, 0x06, 0x40, // TCP protocol
			}, append(
				net.ParseIP("2001:db8::1").To16(),
				append(
					net.ParseIP("2001:db8::2").To16(),
					[]byte{ // TCP header
						0x00, 0x50, 0x20, 0x00,
						0x00, 0x00, 0x00, 0x00,
						0x50, 0x02, 0x20, 0x00,
						0x00, 0x00, 0x00, 0x00,
					}...,
				)...,
			)...),
			len: 60,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &Packet{
				Raw:       tt.raw,
				PacketLen: tt.len,
				Addr:      NewWinDivertAddress(),
			}
			original.ParseHeaders()

			data, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("Failed to marshal packet: %v", err)
			}

			restored := &Packet{}
			err = restored.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal packet: %v", err)
			}

			restored.ParseHeaders()

			if !bytes.Equal(original.Raw, restored.Raw) {
				t.Errorf("Raw packet data doesn't match\nOriginal: %v\nRestored: %v", original.Raw, restored.Raw)
			}
			if original.PacketLen != restored.PacketLen {
				t.Errorf("PacketLen doesn't match: got %d, want %d", restored.PacketLen, original.PacketLen)
			}
			if original.parsed != restored.parsed {
				t.Errorf("Parsed flag doesn't match: got %v, want %v", restored.parsed, original.parsed)
			}
			if original.ipVersion != restored.ipVersion {
				t.Errorf("IP version doesn't match: got %d, want %d", restored.ipVersion, original.ipVersion)
			}

			if original.SrcIP() != nil && restored.SrcIP() != nil {
				if !original.SrcIP().Equal(restored.SrcIP()) {
					t.Errorf("Source IP doesn't match: got %v, want %v", restored.SrcIP(), original.SrcIP())
				}
			}
			if original.DstIP() != nil && restored.DstIP() != nil {
				if !original.DstIP().Equal(restored.DstIP()) {
					t.Errorf("Destination IP doesn't match: got %v, want %v", restored.DstIP(), original.DstIP())
				}
			}

			if original.NextHeaderType() == header.TCP || original.NextHeaderType() == header.UDP {
				origSrcPort, _ := original.SrcPort()
				restSrcPort, _ := restored.SrcPort()
				if origSrcPort != restSrcPort {
					t.Errorf("Source port doesn't match: got %d, want %d", restSrcPort, origSrcPort)
				}

				origDstPort, _ := original.DstPort()
				restDstPort, _ := restored.DstPort()
				if origDstPort != restDstPort {
					t.Errorf("Destination port doesn't match: got %d, want %d", restDstPort, origDstPort)
				}
			}
		})
	}
}

func TestPacketMarshalUnmarshalWithPayload(t *testing.T) {
	tests := []struct {
		name    string
		raw     []byte
		payload []byte
		len     uint
	}{
		{
			name: "TCP with HTTP payload",
			raw: append([]byte{
				0x45, 0x00, 0x00, 0x28, // IPv4 header
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
				0x00, 0x50, 0x20, 0x00, // TCP header
				0x00, 0x00, 0x00, 0x00,
				0x50, 0x02, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}, []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")...),
			payload: []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			len:     uint(32 + len("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")),
		},
		{
			name: "UDP with DNS query",
			raw: append([]byte{
				0x45, 0x00, 0x00, 0x1c, // IPv4 header
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x11, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
				0x00, 0x35, 0x20, 0x00,
				0x00, 0x08, 0x00, 0x00,
			}, []byte{
				0x00, 0x01, 0x01, 0x00, // DNS header
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}...),
			payload: []byte{
				0x00, 0x01, 0x01, 0x00,
				0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
			},
			len: 40,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := &Packet{
				Raw:       tt.raw,
				PacketLen: tt.len,
				Addr:      NewWinDivertAddress(),
			}
			original.ParseHeaders()

			data, err := original.MarshalBinary()
			if err != nil {
				t.Fatalf("Failed to marshal packet: %v", err)
			}

			restored := &Packet{}
			err = restored.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("Failed to unmarshal packet: %v", err)
			}

			originalPayload := original.Raw[len(original.Raw)-len(tt.payload):]
			restoredPayload := restored.Raw[len(restored.Raw)-len(tt.payload):]
			if !bytes.Equal(originalPayload, restoredPayload) {
				t.Errorf("Payload doesn't match\nOriginal: %v\nRestored: %v", originalPayload, restoredPayload)
			}
		})
	}
}

func TestPacketMarshalUnmarshalFuzz(t *testing.T) {
	f := func(rawData []byte, packetLen uint32, timestamp int64, ifIdx, subIfIdx uint32, flags uint8) bool {
		if len(rawData) == 0 {
			return true // Skip empty packets
		}

		if len(rawData) < 20 {
			rawData = append(make([]byte, 20-len(rawData)), rawData...)
		}

		if len(rawData) > 65535 { // Max IP packet size
			rawData = rawData[:65535]
		}

		rawData[0] = 0x45 // Version 4, header length 5 DWORDs (20 bytes)

		binary.BigEndian.PutUint16(rawData[2:4], uint16(len(rawData)))

		if packetLen > uint32(len(rawData)) {
			packetLen = uint32(len(rawData))
		}

		original := &Packet{
			Raw:       rawData,
			PacketLen: uint(packetLen),
			Addr: &WinDivertAddress{
				Timestamp: timestamp,
				IfIdx:     ifIdx,

				SubIfIdx: subIfIdx,
				Flags:    flags,
			},
		}

		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Logf("Recovered from panic during parsing: %v", r)
				}
			}()
			original.ParseHeaders()
		}()

		data, err := original.MarshalBinary()
		if err != nil {
			t.Logf("Marshal error: %v", err)
			return false
		}

		restored := &Packet{}
		if err := restored.UnmarshalBinary(data); err != nil {
			t.Logf("Unmarshal error: %v", err)
			return false
		}

		if !bytes.Equal(original.Raw, restored.Raw) {
			t.Logf("Raw data mismatch: orig len=%d, restored len=%d", len(original.Raw), len(restored.Raw))
			return false
		}
		if original.PacketLen != restored.PacketLen {
			t.Logf("PacketLen mismatch: orig=%d, restored=%d", original.PacketLen, restored.PacketLen)
			return false
		}

		return true
	}

	config := &quick.Config{
		MaxCount: 1000,
		Values: func(values []reflect.Value, r *rand.Rand) {
			size := r.Intn(1481) + 20 // 20-1500 bytes
			rawData := make([]byte, size)
			r.Read(rawData)

			values[0] = reflect.ValueOf(rawData)
			values[1] = reflect.ValueOf(uint32(size))
			values[2] = reflect.ValueOf(r.Int63())
			values[3] = reflect.ValueOf(r.Uint32())
			values[4] = reflect.ValueOf(r.Uint32())
			values[5] = reflect.ValueOf(uint8(r.Intn(256)))
		},
	}

	if err := quick.Check(f, config); err != nil {
		t.Error(err)
	}
}

func TestPacketMarshalUnmarshalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		packet  *Packet
		wantErr bool
	}{
		{
			name: "Empty packet",
			packet: &Packet{
				Raw:       []byte{},
				PacketLen: 0,
				Addr:      NewWinDivertAddress(),
			},
			wantErr: false,
		},
		{
			name: "Minimum size IPv4 packet",
			packet: &Packet{
				Raw: []byte{
					0x45, 0x00, 0x00, 0x14, // 20 bytes header
					0x00, 0x00, 0x40, 0x00,
					0x40, 0x00, 0x00, 0x00,
					0x0a, 0x00, 0x00, 0x01,
					0x0a, 0x00, 0x00, 0x02,
				},
				PacketLen: 20,
				Addr:      NewWinDivertAddress(),
			},
			wantErr: false,
		},
		{
			name: "Large packet",
			packet: &Packet{
				Raw:       make([]byte, 65535), // Maximum IP packet size
				PacketLen: 65535,
				Addr:      NewWinDivertAddress(),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.packet.ParseHeaders()

			data, err := tt.packet.MarshalBinary()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			restored := &Packet{}
			err = restored.UnmarshalBinary(data)
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			if !reflect.DeepEqual(tt.packet.Addr, restored.Addr) {
				t.Error("Restored WinDivertAddress doesn't match original")
			}

			if !bytes.Equal(tt.packet.Raw, restored.Raw) {
				t.Error("Restored packet doesn't match original")
			}
		})
	}
}

func TestPacketUnmarshalCorruptedData(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Nil data",
			data:    nil,
			wantErr: true,
		},
		{
			name:    "Too short data",
			data:    []byte{0x00, 0x01, 0x02},
			wantErr: true,
		},
		{
			name: "Invalid raw length",
			data: append(
				[]byte{
					0x00, 0x00, 0x00, 0x00, // PacketLen
					0xFF, 0xFF, 0xFF, 0xFF, // Invalid raw length
					0x00, // parsed flag
				},
				make([]byte, 100)..., // Some random data
			),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Packet{}
			err := p.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func generateRandomPacket(t *testing.T) *Packet {
	t.Helper()

	isIPv6 := rand.Float32() > 0.5
	var raw []byte

	if isIPv6 {
		raw = make([]byte, 40) // IPv6 header
		raw[0] = 0x60          // Version 6
	} else {
		raw = make([]byte, 20) // IPv4 header
		raw[0] = 0x45          // Version 4
	}

	// Add random payload
	payloadSize := rand.Intn(1000)
	raw = append(raw, make([]byte, payloadSize)...)
	rand.Read(raw[20:]) // Fill with random data

	return &Packet{
		Raw:       raw,
		PacketLen: uint(len(raw)),
		Addr:      NewWinDivertAddress(),
	}
}

func TestPacketRandomGeneration(t *testing.T) {
	for i := 0; i < 100; i++ {
		packet := generateRandomPacket(t)
		packet.ParseHeaders()

		data, err := packet.MarshalBinary()
		if err != nil {
			t.Fatalf("Failed to marshal random packet: %v", err)
		}

		restored := &Packet{}
		if err := restored.UnmarshalBinary(data); err != nil {
			t.Fatalf("Failed to unmarshal random packet: %v", err)
		}

		if !bytes.Equal(packet.Raw, restored.Raw) {
			t.Error("Random packet restoration failed")
		}

		if !reflect.DeepEqual(packet.Addr, restored.Addr) {
			t.Error("Restored WinDivertAddress doesn't match original")
		}
	}
}

func BenchmarkPacketParsing(b *testing.B) {
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
				0x00, 0x50, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x50, 0x02, 0x20, 0x00,
				0x00, 0x00, 0x00, 0x00,
			}, bytes.Repeat([]byte("X"), 1400)...),
		},
		{
			name: "IPv6_TCP",
			raw: append([]byte{
				0x60, 0x00, 0x00, 0x00,
				0x00, 0x14, 0x06, 0x40,
			}, append(
				net.ParseIP("2001:db8::1").To16(),
				append(
					net.ParseIP("2001:db8::2").To16(),
					[]byte{
						0x00, 0x50, 0x20, 0x00,
						0x00, 0x00, 0x00, 0x00,
						0x50, 0x02, 0x20, 0x00,
						0x00, 0x00, 0x00, 0x00,
					}...,
				)...,
			)...),
		},
	}

	for _, p := range packets {
		b.Run(p.name, func(b *testing.B) {
			packet := &Packet{
				Raw:       p.raw,
				PacketLen: uint(len(p.raw)),
				Addr:      NewWinDivertAddress(),
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				packet.parsed = false
				packet.ParseHeaders()
			}
		})
	}
}

func BenchmarkPacketMarshalUnmarshal(b *testing.B) {
	packets := []struct {
		name string
		raw  []byte
	}{
		{
			name: "Small_Packet",
			raw: []byte{
				0x45, 0x00, 0x00, 0x28,
				0x00, 0x00, 0x40, 0x00,
				0x40, 0x06, 0x00, 0x00,
				0x0a, 0x00, 0x00, 0x01,
				0x0a, 0x00, 0x00, 0x02,
			},
		},
		{
			name: "Medium_Packet",
			raw: append([]byte{
				0x45, 0x00, 0x00, 0x28,
			}, bytes.Repeat([]byte{0x00}, 500)...),
		},
		{
			name: "Large_Packet",
			raw: append([]byte{
				0x45, 0x00, 0x00, 0x28,
			}, bytes.Repeat([]byte{0x00}, 1400)...),
		},
	}

	for _, p := range packets {
		b.Run(p.name, func(b *testing.B) {
			packet := &Packet{
				Raw:       p.raw,
				PacketLen: uint(len(p.raw)),
				Addr:      NewWinDivertAddress(),
			}
			packet.ParseHeaders()

			b.ResetTimer()
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

func BenchmarkPacketHeaderAccess(b *testing.B) {
	packet := &Packet{
		Raw: []byte{
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
		PacketLen: 40,
		Addr:      NewWinDivertAddress(),
	}
	packet.ParseHeaders()

	b.Run("SrcIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = packet.SrcIP()
		}
	})

	b.Run("DstIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = packet.DstIP()
		}
	})

	b.Run("SrcPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = packet.SrcPort()
		}
	})

	b.Run("DstPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = packet.DstPort()
		}
	})
}

func BenchmarkPacketModification(b *testing.B) {
	newIP := net.ParseIP("192.168.1.1")
	packet := &Packet{
		Raw: []byte{
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
		PacketLen: 40,
		Addr:      NewWinDivertAddress(),
	}
	packet.ParseHeaders()

	b.Run("SetSrcIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			packet.SetSrcIP(newIP)
		}
	})

	b.Run("SetDstIP", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			packet.SetDstIP(newIP)
		}
	})

	b.Run("SetSrcPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = packet.SetSrcPort(8080)
		}
	})

	b.Run("SetDstPort", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = packet.SetDstPort(8080)
		}
	})
}

func BenchmarkPacketAllocation(b *testing.B) {
	sizes := []int{64, 512, 1500} // Common packet sizes

	for _, size := range sizes {
		b.Run(fmt.Sprintf("Size_%d", size), func(b *testing.B) {
			raw := make([]byte, size)
			rand.Read(raw)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				packet := &Packet{
					Raw:       make([]byte, len(raw)),
					PacketLen: uint(len(raw)),
					Addr:      NewWinDivertAddress(),
				}
				copy(packet.Raw, raw)
				packet.ParseHeaders()
			}
		})
	}
}
