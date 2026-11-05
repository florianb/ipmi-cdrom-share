package smbserver

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// le is the byte order of all SMB fields. The NetBIOS frame header is the only
// big-endian structure and is handled in transport.go.
var le = binary.LittleEndian

// Protocol identifiers, the first four bytes of every message.
var (
	smb1Magic = [4]byte{0xFF, 'S', 'M', 'B'}
	smb2Magic = [4]byte{0xFE, 'S', 'M', 'B'}
)

const (
	// maxBufferSize is the largest payload of a single read, in both SMB1 and SMB2.
	maxBufferSize = 65536

	// fileActionOpened is the CreateAction of every successful open.
	fileActionOpened = 1

	// Values of the file system both protocols pretend to have.
	allocationUnit    = 4096
	sectorsPerUnit    = 8
	bytesPerSector    = 512
	fsAttributeName   = "FAT"
	volumeLabel       = "IPMI CD Share"
	maxFileNameLength = 255
	fileDeviceDisk    = 0x00000007
)

// File attributes.
const (
	fileAttrReadOnly  = 0x00000001
	fileAttrDirectory = 0x00000010
)

// timeToFiletime converts t to a Windows FILETIME.
func timeToFiletime(t time.Time) uint64 {
	// Windows FILETIME: 100ns intervals since 1601-01-01.
	const epochDiff = 116444736000000000
	return uint64(t.UnixNano()/100) + epochDiff
}

// putTimes writes the four timestamps that start the common file information
// layout (creation, last access, last write, change), all set to t.
func putTimes(b []byte, t uint64) {
	for i := 0; i < 4; i++ {
		le.PutUint64(b[8*i:], t)
	}
}

// encodeUTF16LE encodes s as UTF-16LE, without a terminator.
func encodeUTF16LE(s string) []byte {
	codes := utf16.Encode([]rune(s))
	b := make([]byte, len(codes)*2)
	for i, c := range codes {
		le.PutUint16(b[i*2:], c)
	}
	return b
}

// decodeUTF16LE decodes UTF-16LE and drops trailing NUL characters. A last odd byte
// is ignored.
func decodeUTF16LE(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u16 := make([]uint16, len(b)/2)
	for i := range u16 {
		u16[i] = le.Uint16(b[i*2:])
	}
	for len(u16) > 0 && u16[len(u16)-1] == 0 {
		u16 = u16[:len(u16)-1]
	}
	return string(utf16.Decode(u16))
}
