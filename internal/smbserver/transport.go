package smbserver

import (
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"
	"unicode/utf16"
)

const (
	// maxBufferSize is the largest payload of a single read, in both SMB1 and SMB2.
	maxBufferSize = 65536

	frameHeaderSize = 4
	maxFrameSize    = 0x100000

	// pooledBufferSize holds one read response of either protocol: frame
	// header + SMB2 header (64) + READ response (16) + data. It also covers the
	// smaller SMB1 layout (32+1+24+2+1).
	pooledBufferSize = frameHeaderSize + 64 + 16 + maxBufferSize
)

// NetBIOS session service message types.
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

// readFrame reads one NetBIOS session service frame (4-byte header: type + 24-bit length).
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

func putFrameHeader(buf []byte, msgType byte, length int) {
	buf[0] = msgType
	buf[1] = byte(length >> 16)
	buf[2] = byte(length >> 8)
	buf[3] = byte(length)
}

// --- Wire encoding helpers ---

func timeToFiletime(t time.Time) uint64 {
	// Windows FILETIME: 100ns intervals since 1601-01-01.
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

func encodeUTF16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		binary.LittleEndian.PutUint16(b[i*2:], c)
	}
	return b
}

func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
