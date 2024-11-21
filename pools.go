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
	// Specialized pools for common operations
	bufferPools = [...]struct {
		size int
		pool sync.Pool
	}{
		{
			size: 64, // Small packets
			pool: sync.Pool{New: func() interface{} { return make([]byte, 64, 64) }},
		},
		{
			size: 576, // IPv4 minimum MTU
			pool: sync.Pool{New: func() interface{} { return make([]byte, 576, 576) }},
		},
		{
			size: 1500, // Ethernet MTU
			pool: sync.Pool{New: func() interface{} { return make([]byte, 1500, 1500) }},
		},
		{
			size: 9000, // Jumbo frames
			pool: sync.Pool{New: func() interface{} { return make([]byte, 9000, 9000) }},
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

	// Pool for marshal operations
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

// GetBuffer with size class optimization
func GetBuffer(size int) []byte {
	if size > maxBufferSize {
		return make([]byte, size)
	}

	// Binary search for appropriate size class
	left, right := 0, len(bufferPools)-1
	for left <= right {
		mid := (left + right) / 2
		if size <= bufferPools[mid].size {
			if mid == 0 || size > bufferPools[mid-1].size {
				buf := bufferPools[mid].pool.Get().([]byte)
				return buf[:size]
			}
			right = mid - 1
		} else {
			left = mid + 1
		}
	}

	return make([]byte, size)
}

// PutBuffer with optimized size class lookup
func PutBuffer(buf []byte) {
	if cap(buf) > maxBufferSize {
		return
	}

	// Binary search for exact size match
	size := cap(buf)
	left, right := 0, len(bufferPools)-1
	for left <= right {
		mid := (left + right) / 2
		if size == bufferPools[mid].size {
			bufferPools[mid].pool.Put(buf)
			return
		}
		if size < bufferPools[mid].size {
			right = mid - 1
		} else {
			left = mid + 1
		}
	}
}

// GetMarshalBuffer returns a buffer for marshal operations
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

// PutMarshalBuffer returns a marshal buffer to the pool
func PutMarshalBuffer(buf *struct {
	buf  []byte
	hdr  [header.MarshalHeaderSize]byte
	addr [header.AddressSize]byte
}, pooled bool) {
	if pooled {
		marshalPool.Put(buf)
	}
}
