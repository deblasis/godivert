package godivert

import (
	"sync"

	"github.com/deblasis/godivert/header"
)

const (
	defaultBufferSize = 2048
	maxBufferSize     = 65535 + 512 // Max IP packet size + extra space for headers
	MaxPacketSize     = 65535
)

var (
	// Pool for packet raw data buffers
	packetBufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, PacketBufferSize)
			return &b
		},
	}

	// Pool for marshal operations
	marshalBufferPool = sync.Pool{
		New: func() interface{} {
			return &struct {
				buf []byte
				tmp [24]byte // Fixed size for common headers
			}{
				buf: make([]byte, 0, defaultBufferSize),
			}
		},
	}

	// Pool for address marshaling
	addressBufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 24) // WinDivertAddress fixed size
		},
	}

	// Pool for packet objects
	packetPool = sync.Pool{
		New: func() interface{} {
			return &Packet{
				Raw:  make([]byte, 0, defaultBufferSize),
				Addr: NewWinDivertAddress(),
			}
		},
	}

	// Add new pool for marshal operations
	marshalPool = sync.Pool{
		New: func() interface{} {
			return &struct {
				buf  []byte
				hdr  [header.MarshalHeaderSize]byte
				addr [header.AddressSize]byte
			}{
				buf: make([]byte, 0, defaultBufferSize),
			}
		},
	}
)

// GetBuffer gets a buffer from the pool with at least the specified size
func GetBuffer(size int) []byte {
	if size > maxBufferSize {
		return make([]byte, size)
	}

	bufStruct := marshalBufferPool.Get().(*struct {
		buf []byte
		tmp [24]byte
	})

	if cap(bufStruct.buf) < size {
		bufStruct.buf = make([]byte, size)
	}
	bufStruct.buf = bufStruct.buf[:size]
	return bufStruct.buf
}

// PutBuffer returns a buffer to the pool
func PutBuffer(buf []byte) {
	if cap(buf) <= maxBufferSize {
		marshalBufferPool.Put(&struct {
			buf []byte
			tmp [24]byte
		}{
			buf: buf[:0],
		})
	}
}

// Replace GetBuffer with optimized version
func GetMarshalBuffer(size int) (*struct {
	buf  []byte
	hdr  [header.MarshalHeaderSize]byte
	addr [header.AddressSize]byte
}, bool) {
	if size > maxBufferSize {
		return &struct {
			buf  []byte
			hdr  [header.MarshalHeaderSize]byte
			addr [header.AddressSize]byte
		}{
			buf: make([]byte, size),
		}, false
	}

	buf := marshalPool.Get().(*struct {
		buf  []byte
		hdr  [header.MarshalHeaderSize]byte
		addr [header.AddressSize]byte
	})

	if cap(buf.buf) < size {
		buf.buf = make([]byte, size)
	}
	buf.buf = buf.buf[:size]
	return buf, true
}

// Add PutMarshalBuffer
func PutMarshalBuffer(buf *struct {
	buf  []byte
	hdr  [header.MarshalHeaderSize]byte
	addr [header.AddressSize]byte
}, pooled bool) {
	if pooled {
		marshalPool.Put(buf)
	}
}
