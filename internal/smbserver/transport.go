package smbserver

import (
	"fmt"
	"io"
	"sync"
)

const (
	frameHeaderSize = 4
	maxFrameSize    = 0x100000

	// pooledBufferSize holds one read response of either protocol: frame
	// header + SMB2 header (64) + READ response (16) + data. It also covers the
	// smaller SMB1 layout (32+1+24+2+1).
	pooledBufferSize = frameHeaderSize + 64 + 16 + maxBufferSize
)

// NetBIOS session service message types (RFC 1002, 4.3.1).
const (
	frameTypeSessionMessage  = 0x00
	frameTypeSessionRequest  = 0x81
	frameTypePositiveSession = 0x82
)

// readBufPool recycles buffers for read responses to avoid per-request allocations.
var readBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, pooledBufferSize)
		return &b
	},
}

// readFrame reads one frame. The 4-byte header is the same for the NetBIOS session
// service on port 139 and for Direct TCP on port 445 ([MS-SMB2] 2.1): a type byte,
// zero on Direct TCP, and a 24-bit big-endian length.
func readFrame(r io.Reader) (data []byte, msgType byte, err error) {
	var hdr [frameHeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, 0, err
	}
	msgType = hdr[0]
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if length == 0 {
		return nil, msgType, nil
	}
	if length > maxFrameSize {
		return nil, 0, fmt.Errorf("NetBIOS length too large: %d", length)
	}
	data = make([]byte, length)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, 0, err
	}
	return data, msgType, nil
}

// writeFrame writes header and data in a single call to avoid multiple TCP segments.
func writeFrame(w io.Writer, msgType byte, data []byte) error {
	buf := make([]byte, frameHeaderSize+len(data))
	putFrameHeader(buf, msgType, len(data))
	copy(buf[frameHeaderSize:], data)
	_, err := w.Write(buf)
	return err
}

// putFrameHeader writes the 4-byte frame header to buf.
func putFrameHeader(buf []byte, msgType byte, length int) {
	buf[0] = msgType
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
}
