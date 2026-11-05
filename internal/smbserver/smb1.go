package smbserver

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// SMB1 command codes.
const (
	smbComClose            = 0x04
	smbComEcho             = 0x2B
	smbComReadAndX         = 0x2E
	smbComTransaction2     = 0x32
	smbComTreeDisconnect   = 0x71
	smbComNegotiate        = 0x72
	smbComSessionSetupAndX = 0x73
	smbComLogoffAndX       = 0x74
	smbComTreeConnectAndX  = 0x75
	smbComNtCreateAndX     = 0xA2
)

// NT status codes.
const (
	statusOK                 = 0x00000000
	statusNotImplemented     = 0xC0000002
	statusInvalidHandle      = 0xC0000008
	statusObjectNameNotFound = 0xC0000034
)

// SMB flags.
const (
	smbFlagReply      = 0x80
	smbFlagCaseless   = 0x08
	smbFlags2Unicode  = 0x8000
	smbFlags2NTStatus = 0x4000
)

// Capability flags.
const (
	capRawMode    = 0x00000001
	capUnicode    = 0x00000004
	capLargeFiles = 0x00000008
	capNTSMBs     = 0x00000010
	capNTStatus   = 0x00000040
	capLargeReadX = 0x00004000
)

// TRANS2 subcommands.
const (
	trans2FindFirst2    = 0x0001
	trans2QueryFSInfo   = 0x0003
	trans2QueryPathInfo = 0x0005
	trans2QueryFileInfo = 0x0007
)

// Query information levels.
const (
	smbQueryFileBasicInfo    = 0x0101
	smbQueryFileStandardInfo = 0x0102
	smbQueryFileAllInfo      = 0x0107
	smbFindFileBothDirInfo   = 0x0104
)

// Filesystem info levels.
const (
	smbQueryFSSizeInfo      = 0x0103
	smbQueryFSDeviceInfo    = 0x0104
	smbQueryFSAttributeInfo = 0x0105
)

// File attributes.
const (
	fileAttrReadOnly  = 0x00000001
	fileAttrDirectory = 0x00000010
	fileAttrNormal    = 0x00000080
)

// smbHeader is the 32-byte SMB1 header.
type smbHeader struct {
	command  uint8
	status   uint32
	flags    uint8
	flags2   uint16
	pidHigh  uint16
	security [8]byte
	tid      uint16
	pidLow   uint16
	uid      uint16
	mid      uint16
}

// smbPacket is a parsed SMB1 packet.
type smbPacket struct {
	header smbHeader
	words  []byte // parameter words (WordCount * 2 bytes)
	data   []byte // data section (ByteCount bytes)
}

// session holds per-connection SMB1 state.
type session struct {
	file     io.ReaderAt
	fileSize int64
	fileName string
	uid      uint16
	tid      uint16
	fid      uint16
	unicode  bool
	progress *progress
	debug    *debugStats // nil unless --debug
}

func newSMB1Session(s *Server) *session {
	return &session{
		file:     s.share,
		fileSize: s.share.Size(),
		fileName: s.share.Name(),
		uid:      1,
		tid:      1,
		fid:      0x4000,
		progress: s.progress,
		debug:    s.debug,
	}
}

// serve handles one parsed request and writes its response.
func (sess *session) serve(w io.Writer, req *smbPacket) error {
	if req.header.flags2&smbFlags2Unicode != 0 {
		sess.unicode = true
	}

	// Fast path for READ_ANDX: build response in a single pooled buffer.
	if req.header.command == smbComReadAndX {
		var t0 time.Time
		if sess.debug != nil {
			t0 = time.Now()
		}
		wire, poolBuf, ioNs := handleReadFast(sess, req)
		if wire != nil {
			var writeStart time.Time
			if sess.debug != nil {
				writeStart = time.Now()
			}
			_, err := w.Write(wire)
			if sess.debug != nil {
				writeNs := time.Since(writeStart).Nanoseconds()
				totalNs := time.Since(t0).Nanoseconds()
				dataLen := len(wire) - 64 // subtract headers
				sess.debug.requests.Add(1)
				sess.debug.fileBytes.Add(int64(dataLen))
				sess.debug.handlerNs.Add(totalNs)
				sess.debug.ioNs.Add(ioNs)
				sess.debug.writeNs.Add(writeNs)
				sess.debug.recordLatency(totalNs)
				sess.debug.recordSize(dataLen)
			}
			readBufPool.Put(poolBuf)
			if err != nil {
				return fmt.Errorf("write: %w", err)
			}
			return nil
		}
		// Fall through to normal dispatch for error responses.
	}

	resp := dispatchCommand(sess, req)
	if resp == nil {
		return nil
	}
	if err := writeFrame(w, frameTypeSessionMessage, buildSMBResponse(resp)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// smb1Dialects returns the dialect strings of an SMB1 NEGOTIATE data section.
func smb1Dialects(data []byte) []string {
	var dialects []string
	for pos := 0; pos < len(data) && data[pos] == 0x02; {
		pos++
		end := pos
		for end < len(data) && data[end] != 0x00 {
			end++
		}
		dialects = append(dialects, string(data[pos:end]))
		pos = end + 1
	}
	return dialects
}

// selectMultiProtocolDialect decides whether an SMB1 NEGOTIATE upgrades to SMB2.
// It returns the SMB2 dialect to answer with, or 0 to stay on SMB1. Offering
// NT LM 0.12 always keeps a client on SMB1, so existing BMCs see no change.
func selectMultiProtocolDialect(data []byte) uint16 {
	var dialect uint16
	for _, d := range smb1Dialects(data) {
		switch d {
		case "NT LM 0.12":
			return 0
		case "SMB 2.???":
			dialect = smb2DialectWildcard
		case "SMB 2.002":
			if dialect == 0 {
				dialect = smb2Dialect202
			}
		}
	}
	return dialect
}

// --- SMB packet parse/build ---

func parseSMBPacket(data []byte) (*smbPacket, error) {
	if len(data) < 35 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	if data[0] != 0xFF || data[1] != 'S' || data[2] != 'M' || data[3] != 'B' {
		return nil, fmt.Errorf("invalid SMB magic")
	}

	pkt := &smbPacket{}
	pkt.header.command = data[4]
	pkt.header.status = binary.LittleEndian.Uint32(data[5:9])
	pkt.header.flags = data[9]
	pkt.header.flags2 = binary.LittleEndian.Uint16(data[10:12])
	pkt.header.pidHigh = binary.LittleEndian.Uint16(data[12:14])
	copy(pkt.header.security[:], data[14:22])
	pkt.header.tid = binary.LittleEndian.Uint16(data[24:26])
	pkt.header.pidLow = binary.LittleEndian.Uint16(data[26:28])
	pkt.header.uid = binary.LittleEndian.Uint16(data[28:30])
	pkt.header.mid = binary.LittleEndian.Uint16(data[30:32])

	wordCount := int(data[32])
	wordsEnd := 33 + wordCount*2
	if len(data) < wordsEnd+2 {
		return nil, fmt.Errorf("packet truncated at words")
	}
	pkt.words = data[33:wordsEnd]

	byteCount := int(binary.LittleEndian.Uint16(data[wordsEnd : wordsEnd+2]))
	dataStart := wordsEnd + 2
	dataEnd := dataStart + byteCount
	if dataEnd > len(data) {
		dataEnd = len(data)
	}
	if dataStart <= len(data) {
		pkt.data = data[dataStart:dataEnd]
	}

	return pkt, nil
}

func buildSMBResponse(pkt *smbPacket) []byte {
	if pkt.words == nil {
		pkt.words = []byte{}
	}
	if pkt.data == nil {
		pkt.data = []byte{}
	}

	wordCount := len(pkt.words) / 2
	buf := make([]byte, 32+1+len(pkt.words)+2+len(pkt.data))

	buf[0] = 0xFF
	buf[1] = 'S'
	buf[2] = 'M'
	buf[3] = 'B'
	buf[4] = pkt.header.command
	binary.LittleEndian.PutUint32(buf[5:9], pkt.header.status)
	buf[9] = pkt.header.flags
	binary.LittleEndian.PutUint16(buf[10:12], pkt.header.flags2)
	binary.LittleEndian.PutUint16(buf[12:14], pkt.header.pidHigh)
	copy(buf[14:22], pkt.header.security[:])
	binary.LittleEndian.PutUint16(buf[24:26], pkt.header.tid)
	binary.LittleEndian.PutUint16(buf[26:28], pkt.header.pidLow)
	binary.LittleEndian.PutUint16(buf[28:30], pkt.header.uid)
	binary.LittleEndian.PutUint16(buf[30:32], pkt.header.mid)

	buf[32] = byte(wordCount)
	copy(buf[33:], pkt.words)
	binary.LittleEndian.PutUint16(buf[33+len(pkt.words):], uint16(len(pkt.data)))
	copy(buf[35+len(pkt.words):], pkt.data)

	return buf
}

// --- Command dispatch ---

func dispatchCommand(sess *session, req *smbPacket) *smbPacket {
	switch req.header.command {
	case smbComNegotiate:
		return handleNegotiate(sess, req)
	case smbComSessionSetupAndX:
		return handleSessionSetup(sess, req)
	case smbComTreeConnectAndX:
		return handleTreeConnect(sess, req)
	case smbComNtCreateAndX:
		return handleNtCreate(sess, req)
	case smbComReadAndX:
		return handleRead(sess, req)
	case smbComClose:
		return handleClose(sess, req)
	case smbComTransaction2:
		return handleTrans2(sess, req)
	case smbComTreeDisconnect:
		return handleTreeDisconnect(sess, req)
	case smbComLogoffAndX:
		return handleLogoff(sess, req)
	case smbComEcho:
		return handleEcho(sess, req)
	default:
		log.Printf("Unhandled command: 0x%02X", req.header.command)
		return errorResponse(req, statusNotImplemented)
	}
}

func newResponse(req *smbPacket) *smbPacket {
	resp := &smbPacket{}
	resp.header = req.header
	resp.header.flags = smbFlagReply | (req.header.flags & smbFlagCaseless)
	resp.header.flags2 = req.header.flags2 & (smbFlags2Unicode | smbFlags2NTStatus)
	resp.header.status = statusOK
	return resp
}

func errorResponse(req *smbPacket, status uint32) *smbPacket {
	resp := newResponse(req)
	resp.header.status = status
	return resp
}

// --- NEGOTIATE (0x72) ---

func handleNegotiate(sess *session, req *smbPacket) *smbPacket {
	// Find "NT LM 0.12" dialect.
	dialectIndex := uint16(0xFFFF)
	idx := uint16(0)
	pos := 0
	for pos < len(req.data) {
		if req.data[pos] != 0x02 {
			break
		}
		pos++
		end := pos
		for end < len(req.data) && req.data[end] != 0x00 {
			end++
		}
		if string(req.data[pos:end]) == "NT LM 0.12" {
			dialectIndex = idx
		}
		idx++
		pos = end + 1
	}

	if dialectIndex == 0xFFFF {
		log.Printf("Warning: NT LM 0.12 dialect not found in client request")
	}

	resp := newResponse(req)
	resp.header.flags2 = smbFlags2Unicode | smbFlags2NTStatus

	// WordCount = 17 (34 bytes).
	words := make([]byte, 34)
	binary.LittleEndian.PutUint16(words[0:2], dialectIndex)
	words[2] = 0x00 // SecurityMode: share-level, no passwords
	binary.LittleEndian.PutUint16(words[3:5], 50)
	binary.LittleEndian.PutUint16(words[5:7], 1)
	binary.LittleEndian.PutUint32(words[7:11], maxBufferSize)
	binary.LittleEndian.PutUint32(words[11:15], maxBufferSize)
	binary.LittleEndian.PutUint32(words[15:19], 0) // SessionKey
	caps := uint32(capRawMode | capUnicode | capLargeFiles | capNTSMBs | capNTStatus | capLargeReadX)
	binary.LittleEndian.PutUint32(words[19:23], caps)
	binary.LittleEndian.PutUint64(words[23:31], timeToFiletime(time.Now()))
	binary.LittleEndian.PutUint16(words[31:33], 0) // ServerTimeZone (UTC)
	words[33] = 0                                  // ChallengeLength
	resp.words = words

	// Data: pad for Unicode alignment + empty domain + empty server.
	// Offset to data start: 32+1+34+2 = 69 (odd), need pad byte.
	resp.data = []byte{0x00, 0x00, 0x00, 0x00, 0x00} // pad + 2 Unicode nulls

	sess.unicode = true
	return resp
}

// --- SESSION_SETUP_ANDX (0x73) ---

func handleSessionSetup(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.uid = sess.uid

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = 0xFF                                   // AndXCommand: none
	binary.LittleEndian.PutUint16(words[4:6], 0x0001) // Action: guest
	resp.words = words

	if sess.unicode {
		// Offset to data: 32+1+6+2=41 (odd), need pad.
		var data []byte
		data = append(data, 0x00) // pad
		data = append(data, encodeUTF16LE("Unix")...)
		data = append(data, 0x00, 0x00)
		data = append(data, encodeUTF16LE("IPMI CD Share")...)
		data = append(data, 0x00, 0x00)
		data = append(data, encodeUTF16LE("WORKGROUP")...)
		data = append(data, 0x00, 0x00)
		resp.data = data
	} else {
		resp.data = []byte("Unix\x00IPMI CD Share\x00WORKGROUP\x00")
	}

	return resp
}

// --- TREE_CONNECT_ANDX (0x75) ---

func handleTreeConnect(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.tid = sess.tid

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = 0xFF // AndXCommand: none
	resp.words = words

	// Service type "A:" (disk share) + native filesystem.
	resp.data = []byte("A:\x00FAT\x00")
	return resp
}

// --- NT_CREATE_ANDX (0xA2) ---

func handleNtCreate(sess *session, req *smbPacket) *smbPacket {
	fileName := extractCreateFileName(sess, req)
	log.Printf("NT_CREATE: %q", fileName)

	// Root directory request.
	if fileName == "" {
		return ntCreateDirResponse(sess, req)
	}

	// Match against our served file.
	if !strings.EqualFold(fileName, sess.fileName) {
		return errorResponse(req, statusObjectNameNotFound)
	}

	resp := newResponse(req)
	resp.header.tid = sess.tid
	now := timeToFiletime(time.Now())

	// WordCount = 34 (68 bytes).
	words := make([]byte, 68)
	words[0] = 0xFF // AndXCommand: none
	binary.LittleEndian.PutUint16(words[5:7], sess.fid)
	binary.LittleEndian.PutUint32(words[7:11], 1) // CreateAction: opened
	binary.LittleEndian.PutUint64(words[11:19], now)
	binary.LittleEndian.PutUint64(words[19:27], now)
	binary.LittleEndian.PutUint64(words[27:35], now)
	binary.LittleEndian.PutUint64(words[35:43], now)
	binary.LittleEndian.PutUint32(words[43:47], fileAttrReadOnly)
	binary.LittleEndian.PutUint64(words[47:55], uint64(sess.fileSize))
	binary.LittleEndian.PutUint64(words[55:63], uint64(sess.fileSize))
	// FileType(2)=0, DeviceState(2)=0, Directory(1)=0 are already zero.
	resp.words = words
	return resp
}

func ntCreateDirResponse(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	resp.header.tid = sess.tid
	now := timeToFiletime(time.Now())

	words := make([]byte, 68)
	words[0] = 0xFF
	binary.LittleEndian.PutUint16(words[5:7], 0x4001) // FID for directory
	binary.LittleEndian.PutUint32(words[7:11], 1)
	binary.LittleEndian.PutUint64(words[11:19], now)
	binary.LittleEndian.PutUint64(words[19:27], now)
	binary.LittleEndian.PutUint64(words[27:35], now)
	binary.LittleEndian.PutUint64(words[35:43], now)
	binary.LittleEndian.PutUint32(words[43:47], fileAttrDirectory)
	words[67] = 1 // Directory = true
	resp.words = words
	return resp
}

func extractCreateFileName(sess *session, req *smbPacket) string {
	if len(req.words) < 48 {
		return ""
	}
	nameLen := int(binary.LittleEndian.Uint16(req.words[5:7]))
	if nameLen == 0 || len(req.data) == 0 {
		return ""
	}

	nameData := req.data
	// Skip Unicode alignment pad byte.
	if sess.unicode && len(nameData) > 0 && nameData[0] == 0 {
		nameData = nameData[1:]
	}

	var name string
	if sess.unicode {
		if len(nameData) >= nameLen {
			name = decodeUTF16LE(nameData[:nameLen])
		} else {
			name = decodeUTF16LE(nameData)
		}
	} else {
		if len(nameData) >= nameLen {
			name = string(nameData[:nameLen])
		} else {
			name = string(nameData)
		}
	}

	name = strings.TrimPrefix(name, "\\")
	name = strings.TrimPrefix(name, "/")
	name = strings.TrimRight(name, "\x00")
	return name
}

// --- READ_ANDX (0x2E) ---

// handleReadFast builds the complete wire-format response (NetBIOS header + SMB + data)
// in a single pooled buffer with zero intermediate allocations. It returns the raw bytes
// to write and the pool buffer to recycle, or nil if the request should fall back to the
// normal path (e.g. for error responses).
func handleReadFast(sess *session, req *smbPacket) (wire []byte, poolBuf *[]byte, ioNs int64) {
	if len(req.words) < 20 {
		return nil, nil, 0
	}

	fid := binary.LittleEndian.Uint16(req.words[4:6])
	if fid != sess.fid {
		return nil, nil, 0
	}

	offsetLow := binary.LittleEndian.Uint32(req.words[6:10])
	maxCount := int(binary.LittleEndian.Uint16(req.words[10:12]))
	offset := int64(offsetLow)

	// 64-bit offset support (WordCount >= 12).
	if len(req.words) >= 24 {
		offsetHigh := binary.LittleEndian.Uint32(req.words[20:24])
		offset = int64(offsetHigh)<<32 | int64(offsetLow)
	}

	// Clamp read size.
	maxData := maxBufferSize - 60 // leave room for headers
	if maxCount > maxData {
		maxCount = maxData
	}
	if offset >= sess.fileSize {
		maxCount = 0
	} else if offset+int64(maxCount) > sess.fileSize {
		maxCount = int(sess.fileSize - offset)
	}

	// Get a pooled buffer. Layout:
	//   [0:4]     NetBIOS header
	//   [4:36]    SMB header (32 bytes)
	//   [36]      WordCount = 12
	//   [37:61]   Words (24 bytes)
	//   [61:63]   ByteCount
	//   [63]      Pad byte
	//   [64:]     File data
	const hdrSize = 4 + 32 + 1 + 24 + 2 + 1 // = 64
	bp := readBufPool.Get().(*[]byte)
	buf := *bp

	// Read file data directly into the final position.
	n := 0
	if maxCount > 0 {
		var ioStart time.Time
		if sess.debug != nil {
			ioStart = time.Now()
		}
		var err error
		n, err = sess.file.ReadAt(buf[hdrSize:hdrSize+maxCount], offset)
		if sess.debug != nil {
			ioNs = time.Since(ioStart).Nanoseconds()
		}
		if err != nil && !errors.Is(err, io.EOF) {
			log.Printf("ReadAt error at offset %d: %v", offset, err)
			n = 0
		}
		if n > 0 && sess.progress != nil {
			select {
			case sess.progress.events <- readEvent{offset: offset, size: n}:
			default:
			}
		}
	}

	// Total SMB payload size (everything after NetBIOS header).
	smbLen := 32 + 1 + 24 + 2 + 1 + n // = 60 + n
	totalLen := 4 + smbLen

	// NetBIOS header.
	buf[0] = 0x00
	buf[1] = byte(smbLen >> 16)
	buf[2] = byte(smbLen >> 8)
	buf[3] = byte(smbLen)

	// SMB header at offset 4.
	smb := buf[4:]
	smb[0] = 0xFF
	smb[1] = 'S'
	smb[2] = 'M'
	smb[3] = 'B'
	smb[4] = req.header.command
	binary.LittleEndian.PutUint32(smb[5:9], statusOK)
	smb[9] = smbFlagReply | (req.header.flags & smbFlagCaseless)
	binary.LittleEndian.PutUint16(smb[10:12], req.header.flags2&(smbFlags2Unicode|smbFlags2NTStatus))
	binary.LittleEndian.PutUint16(smb[12:14], req.header.pidHigh)
	copy(smb[14:22], req.header.security[:])
	smb[22] = 0
	smb[23] = 0
	binary.LittleEndian.PutUint16(smb[24:26], req.header.tid)
	binary.LittleEndian.PutUint16(smb[26:28], req.header.pidLow)
	binary.LittleEndian.PutUint16(smb[28:30], req.header.uid)
	binary.LittleEndian.PutUint16(smb[30:32], req.header.mid)

	// WordCount = 12.
	smb[32] = 12

	// Words at smb[33:57] (24 bytes).
	words := smb[33:57]
	// Zero out words region.
	for i := range words {
		words[i] = 0
	}
	words[0] = 0xFF                                        // AndXCommand: none
	binary.LittleEndian.PutUint16(words[4:6], 0xFFFF)      // Remaining
	binary.LittleEndian.PutUint16(words[10:12], uint16(n)) // DataLength
	binary.LittleEndian.PutUint16(words[12:14], 60)        // DataOffset

	// ByteCount = 1 (pad) + n.
	binary.LittleEndian.PutUint16(smb[57:59], uint16(1+n))

	// Pad byte.
	smb[59] = 0x00

	// File data is already at smb[60:60+n] from ReadAt above.

	return buf[:totalLen], bp, ioNs
}

// handleRead is the fallback for error cases.
func handleRead(sess *session, req *smbPacket) *smbPacket {
	if len(req.words) < 20 {
		return errorResponse(req, statusInvalidHandle)
	}
	fid := binary.LittleEndian.Uint16(req.words[4:6])
	if fid != sess.fid {
		return errorResponse(req, statusInvalidHandle)
	}
	return errorResponse(req, statusInvalidHandle)
}

// --- CLOSE (0x04) ---

func handleClose(sess *session, req *smbPacket) *smbPacket {
	return newResponse(req)
}

// --- TREE_DISCONNECT (0x71) ---

func handleTreeDisconnect(sess *session, req *smbPacket) *smbPacket {
	return newResponse(req)
}

// --- LOGOFF_ANDX (0x74) ---

func handleLogoff(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	words := make([]byte, 4)
	words[0] = 0xFF // AndXCommand: none
	resp.words = words
	return resp
}

// --- ECHO (0x2B) ---

func handleEcho(sess *session, req *smbPacket) *smbPacket {
	resp := newResponse(req)
	words := make([]byte, 2)
	binary.LittleEndian.PutUint16(words[0:2], 1) // SequenceNumber
	resp.words = words
	resp.data = req.data
	return resp
}
