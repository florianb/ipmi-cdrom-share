package smbserver

import (
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

// Dialect strings of an SMB1 NEGOTIATE request.
const (
	smb1DialectNTLM     = "NT LM 0.12"
	smb1DialectWildcard = "SMB 2.???"
	smb1Dialect2002     = "SMB 2.002"
)

// Fixed identifiers: a connection has one logical session, one tree and one file,
// so nothing has to be allocated or tracked.
const (
	smb1UID     = 1
	smb1TID     = 1
	smb1FileFID = 0x4000
	smb1DirFID  = 0x4001
)

const (
	smb1HeaderSize = 32

	// smbAndXNone in the AndXCommand word means that no chained command follows.
	smbAndXNone = 0xFF

	smb1ReadWordsSize = 24

	// smb1ReadDataOffset is where file data starts in a READ_ANDX response,
	// relative to the SMB header: header, WordCount, words, ByteCount, pad.
	smb1ReadDataOffset = smb1HeaderSize + 1 + smb1ReadWordsSize + 2 + 1

	// smb1MaxRead keeps a whole READ_ANDX response within maxBufferSize.
	smb1MaxRead = maxBufferSize - smb1ReadDataOffset
)

// smbHeader is the 32-byte SMB1 header ([MS-CIFS] 2.2.3.1). The two bytes at offset
// 22 are reserved.
type smbHeader struct {
	command  uint8
	status   ntStatus
	flags    uint8
	flags2   uint16
	pidHigh  uint16
	security [8]byte
	tid      uint16
	pidLow   uint16
	uid      uint16
	mid      uint16
}

// response returns the header answering h. It echoes the IDs, which is how
// clients match responses to requests.
func (h smbHeader) response() smbHeader {
	h.flags = smbFlagReply | (h.flags & smbFlagCaseless)
	h.flags2 &= smbFlags2Unicode | smbFlags2NTStatus
	h.status = statusOK
	return h
}

// put writes the header to the first 32 bytes of b, which may hold stale data.
func (h *smbHeader) put(b []byte) {
	copy(b, smb1Magic[:])
	b[4] = h.command
	le.PutUint32(b[5:], uint32(h.status))
	b[9] = h.flags
	le.PutUint16(b[10:], h.flags2)
	le.PutUint16(b[12:], h.pidHigh)
	copy(b[14:22], h.security[:])
	b[22], b[23] = 0, 0
	le.PutUint16(b[24:], h.tid)
	le.PutUint16(b[26:], h.pidLow)
	le.PutUint16(b[28:], h.uid)
	le.PutUint16(b[30:], h.mid)
}

// smbPacket is a parsed SMB1 packet.
type smbPacket struct {
	header smbHeader
	words  []byte // parameter words (WordCount * 2 bytes)
	data   []byte // data section (ByteCount bytes)
}

// smb1Session holds per-connection SMB1 state.
type smb1Session struct {
	srv     *Server
	unicode bool // strings are UTF-16; stays set once a request or NEGOTIATE asks for it
}

// newSMB1Session returns the SMB1 state for a new connection to s.
func newSMB1Session(s *Server) *smb1Session {
	return &smb1Session{srv: s}
}

// serve handles one parsed request and writes its response. Reads of the open file
// take their own path to avoid copying the data; all other requests, including
// invalid reads, go through dispatch.
func (sess *smb1Session) serve(w io.Writer, req *smbPacket) error {
	if req.header.flags2&smbFlags2Unicode != 0 {
		sess.unicode = true
	}

	if req.header.command == smbComReadAndX {
		if r, ok := parseSMB1Read(req.words); ok && r.fid == smb1FileFID {
			return sess.serveRead(w, req, r)
		}
	}

	resp, status := sess.dispatch(req)
	if status != statusOK {
		resp = errorResponse(req, status)
	}
	if err := writeFrame(w, frameTypeSessionMessage, buildSMBResponse(resp)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// smb1Dialects returns the dialect strings of an SMB1 NEGOTIATE data section, each
// a 0x02 byte and a NUL-terminated string. Parsing stops at any other byte.
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

// selectMultiProtocolDialect decides whether an SMB1 NEGOTIATE upgrades to SMB2
// ([MS-SMB2] 3.3.5.3).
// It returns the SMB2 dialect to answer with, or 0 to stay on SMB1. Offering
// NT LM 0.12 always keeps a client on SMB1, so existing BMCs see no change.
func selectMultiProtocolDialect(data []byte) uint16 {
	var dialect uint16
	for _, d := range smb1Dialects(data) {
		switch d {
		case smb1DialectNTLM:
			return 0
		case smb1DialectWildcard:
			dialect = smb2DialectWildcard
		case smb1Dialect2002:
			if dialect == 0 {
				dialect = smb2Dialect202
			}
		}
	}
	return dialect
}

// --- SMB packet parse/build ---

// parseSMBPacket parses one SMB1 message. The data section is cut off at the end
// of the frame if ByteCount claims more.
func parseSMBPacket(data []byte) (*smbPacket, error) {
	if len(data) < smb1HeaderSize+3 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}
	if [4]byte(data[:4]) != smb1Magic {
		return nil, fmt.Errorf("invalid SMB magic")
	}

	pkt := &smbPacket{}
	pkt.header.command = data[4]
	pkt.header.status = ntStatus(le.Uint32(data[5:]))
	pkt.header.flags = data[9]
	pkt.header.flags2 = le.Uint16(data[10:])
	pkt.header.pidHigh = le.Uint16(data[12:])
	copy(pkt.header.security[:], data[14:22])
	pkt.header.tid = le.Uint16(data[24:])
	pkt.header.pidLow = le.Uint16(data[26:])
	pkt.header.uid = le.Uint16(data[28:])
	pkt.header.mid = le.Uint16(data[30:])

	wordCount := int(data[smb1HeaderSize])
	wordsEnd := smb1HeaderSize + 1 + wordCount*2
	if len(data) < wordsEnd+2 {
		return nil, fmt.Errorf("packet truncated at words")
	}
	pkt.words = data[smb1HeaderSize+1 : wordsEnd]

	byteCount := int(le.Uint16(data[wordsEnd:]))
	dataStart := wordsEnd + 2
	pkt.data = data[dataStart:min(dataStart+byteCount, len(data))]
	return pkt, nil
}

// buildSMBResponse serializes a packet.
func buildSMBResponse(pkt *smbPacket) []byte {
	buf := make([]byte, smb1HeaderSize+1+len(pkt.words)+2+len(pkt.data))
	pkt.header.put(buf)
	buf[smb1HeaderSize] = byte(len(pkt.words) / 2)
	copy(buf[smb1HeaderSize+1:], pkt.words)
	le.PutUint16(buf[smb1HeaderSize+1+len(pkt.words):], uint16(len(pkt.data)))
	copy(buf[smb1HeaderSize+1+len(pkt.words)+2:], pkt.data)
	return buf
}

// --- Command dispatch ---

// dispatch runs the handler of req. Like in SMB2, a handler returns its response
// and a status; every failure status gets the same empty error response.
func (sess *smb1Session) dispatch(req *smbPacket) (*smbPacket, ntStatus) {
	switch req.header.command {
	case smbComNegotiate:
		return sess.handleNegotiate(req)
	case smbComSessionSetupAndX:
		return sess.handleSessionSetup(req)
	case smbComTreeConnectAndX:
		return sess.handleTreeConnect(req)
	case smbComNtCreateAndX:
		return sess.handleNtCreate(req)
	case smbComReadAndX:
		// serve has already answered every read of the open file.
		return nil, statusInvalidHandle
	case smbComClose:
		return newResponse(req), statusOK
	case smbComTransaction2:
		return sess.handleTrans2(req)
	case smbComTreeDisconnect:
		return newResponse(req), statusOK
	case smbComLogoffAndX:
		return sess.handleLogoff(req)
	case smbComEcho:
		return sess.handleEcho(req)
	default:
		log.Printf("Unhandled command: 0x%02X", req.header.command)
		return nil, statusNotImplemented
	}
}

// newResponse returns an empty success response to req.
func newResponse(req *smbPacket) *smbPacket {
	return &smbPacket{header: req.header.response()}
}

// errorResponse returns the response for a failed request, which has no parameters.
func errorResponse(req *smbPacket, status ntStatus) *smbPacket {
	resp := newResponse(req)
	resp.header.status = status
	return resp
}

// --- NEGOTIATE (0x72) ---

// handleNegotiate answers SMB_COM_NEGOTIATE ([MS-CIFS] 2.2.4.52) with the NT LM 0.12
// response layout: DialectIndex at 0, SecurityMode at 2, MaxMpxCount at 3,
// MaxNumberVcs at 5, MaxBufferSize at 7, MaxRawSize at 11, SessionKey at 15,
// Capabilities at 19, SystemTime at 23, ServerTimeZone at 31 and ChallengeLength at
// 33. If a dialect is offered twice the last one counts. Without NT LM 0.12 the index
// is 0xFFFF, the specified "no dialect" answer, but the words keep their usual layout.
func (sess *smb1Session) handleNegotiate(req *smbPacket) (*smbPacket, ntStatus) {
	dialectIndex := uint16(0xFFFF)
	for i, d := range smb1Dialects(req.data) {
		if d == smb1DialectNTLM {
			dialectIndex = uint16(i)
		}
	}
	if dialectIndex == 0xFFFF {
		log.Printf("Warning: NT LM 0.12 dialect not found in client request")
	}

	resp := newResponse(req)
	resp.header.flags2 = smbFlags2Unicode | smbFlags2NTStatus

	// WordCount = 17 (34 bytes).
	words := make([]byte, 34)
	le.PutUint16(words[0:], dialectIndex)
	words[2] = 0x00             // SecurityMode: share-level, no passwords
	le.PutUint16(words[3:], 50) // MaxMpxCount
	le.PutUint16(words[5:], 1)  // MaxNumberVcs
	le.PutUint32(words[7:], maxBufferSize)
	le.PutUint32(words[11:], maxBufferSize)
	// SessionKey at 15 stays zero.
	le.PutUint32(words[19:], capRawMode|capUnicode|capLargeFiles|capNTSMBs|capNTStatus|capLargeReadX)
	le.PutUint64(words[23:], timeToFiletime(time.Now()))
	// ServerTimeZone at 31 (UTC) and ChallengeLength at 33 stay zero.
	resp.words = words

	// Data: pad for Unicode alignment + empty domain + empty server.
	// Offset to data start: 32+1+34+2 = 69 (odd), need pad byte.
	resp.data = []byte{0x00, 0x00, 0x00, 0x00, 0x00} // pad + 2 Unicode nulls

	sess.unicode = true
	return resp, statusOK
}

// --- SESSION_SETUP_ANDX (0x73) ---

// handleSessionSetup answers SMB_COM_SESSION_SETUP_ANDX ([MS-CIFS] 2.2.4.53). The
// request is not looked at: any credentials become a guest (Action at 4).
func (sess *smb1Session) handleSessionSetup(req *smbPacket) (*smbPacket, ntStatus) {
	resp := newResponse(req)
	resp.header.uid = smb1UID

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = smbAndXNone
	le.PutUint16(words[4:], 0x0001) // Action: guest
	resp.words = words

	// NativeOS, NativeLanMan and PrimaryDomain, purely informational.
	strs := []string{"Unix", volumeLabel, ntlmDomainName}
	if sess.unicode {
		// Offset to data: 32+1+6+2=41 (odd), need pad.
		data := []byte{0x00}
		for _, s := range strs {
			data = append(append(data, encodeUTF16LE(s)...), 0x00, 0x00)
		}
		resp.data = data
	} else {
		resp.data = []byte(strings.Join(strs, "\x00") + "\x00")
	}
	return resp, statusOK
}

// --- TREE_CONNECT_ANDX (0x75) ---

// handleTreeConnect answers SMB_COM_TREE_CONNECT_ANDX ([MS-CIFS] 2.2.4.55). Any share
// name is accepted, since there is only one thing to connect to.
func (sess *smb1Session) handleTreeConnect(req *smbPacket) (*smbPacket, ntStatus) {
	resp := newResponse(req)
	resp.header.tid = smb1TID

	// WordCount = 3 (6 bytes).
	words := make([]byte, 6)
	words[0] = smbAndXNone
	resp.words = words

	// Service type "A:" (disk share) + native filesystem.
	resp.data = []byte("A:\x00" + fsAttributeName + "\x00")
	return resp, statusOK
}

// --- NT_CREATE_ANDX (0xA2) ---

// handleNtCreate answers SMB_COM_NT_CREATE_ANDX ([MS-CIFS] 2.2.4.64). It opens the
// file or, for an empty name, the root directory. Opening holds no state: the FID is
// fixed, and CLOSE has nothing to do. Desired access is ignored, but no command that
// writes exists.
func (sess *smb1Session) handleNtCreate(req *smbPacket) (*smbPacket, ntStatus) {
	fileName := sess.createFileName(req)
	log.Printf("NT_CREATE: %q", fileName)

	if fileName == "" {
		return ntCreateResponse(req, smb1DirFID, fileAttrDirectory, 0), statusOK
	}
	share := sess.srv.share
	if !strings.EqualFold(fileName, share.Name()) {
		return nil, statusObjectNameNotFound
	}
	return ntCreateResponse(req, smb1FileFID, fileAttrReadOnly, share.Size()), statusOK
}

// ntCreateResponse builds the response for a successful open of the file or the
// root directory.
func ntCreateResponse(req *smbPacket, fid uint16, attributes uint32, size int64) *smbPacket {
	resp := newResponse(req)
	resp.header.tid = smb1TID

	// WordCount = 34 (68 bytes). OplockLevel at 4, FileType at 63 and DeviceState
	// at 65 stay zero.
	words := make([]byte, 68)
	words[0] = smbAndXNone
	le.PutUint16(words[5:], fid)
	le.PutUint32(words[7:], fileActionOpened)
	putTimes(words[11:], timeToFiletime(time.Now()))
	le.PutUint32(words[43:], attributes)
	le.PutUint64(words[47:], uint64(size)) // AllocationSize
	le.PutUint64(words[55:], uint64(size)) // EndOfFile
	if attributes&fileAttrDirectory != 0 {
		words[67] = 1
	}
	resp.words = words
	return resp
}

// createFileName returns the name in an NT_CREATE_ANDX request without its
// leading separator. It is empty for the root and for a request without a name.
func (sess *smb1Session) createFileName(req *smbPacket) string {
	if len(req.words) < 48 {
		return ""
	}
	nameLen := int(le.Uint16(req.words[5:]))
	if nameLen == 0 || len(req.data) == 0 {
		return ""
	}

	nameData := req.data
	// Skip Unicode alignment pad byte.
	if sess.unicode && nameData[0] == 0 {
		nameData = nameData[1:]
	}
	name := sess.decodeString(nameData[:min(nameLen, len(nameData))])
	name = strings.TrimPrefix(name, "\\")
	return strings.TrimPrefix(name, "/")
}

// decodeString decodes a client string in the session's encoding without its
// terminator.
func (sess *smb1Session) decodeString(b []byte) string {
	if sess.unicode {
		return decodeUTF16LE(b)
	}
	return strings.TrimRight(string(b), "\x00")
}

// encodeString encodes a server string in the session's encoding, unterminated.
func (sess *smb1Session) encodeString(s string) []byte {
	if sess.unicode {
		return encodeUTF16LE(s)
	}
	return []byte(s)
}

// --- READ_ANDX (0x2E) ---

// smb1ReadRequest holds the fields of a READ_ANDX request.
type smb1ReadRequest struct {
	fid    uint16
	offset int64
	count  int
}

// parseSMB1Read reads the parameter words of SMB_COM_READ_ANDX ([MS-CIFS] 2.2.4.42):
// FID at 4, Offset at 6, MaxCountOfBytesToReturn at 10 and OffsetHigh at 20. Only
// the longer form with 24 bytes has OffsetHigh, which files above 4 GiB need.
func parseSMB1Read(words []byte) (smb1ReadRequest, bool) {
	if len(words) < 20 {
		return smb1ReadRequest{}, false
	}
	r := smb1ReadRequest{
		fid:    le.Uint16(words[4:]),
		offset: int64(le.Uint32(words[6:])),
		count:  int(le.Uint16(words[10:])),
	}
	if len(words) >= smb1ReadWordsSize {
		r.offset |= int64(le.Uint32(words[20:])) << 32
	}
	return r, true
}

// serveRead answers a read of the open file. The response is built around the
// file data in one pooled buffer, without intermediate allocations:
//
//	[0:4]    NetBIOS header
//	[4:36]   SMB header
//	[36]     WordCount = 12
//	[37:61]  words
//	[61:63]  ByteCount
//	[63]     pad byte
//	[64:]    file data
func (sess *smb1Session) serveRead(w io.Writer, req *smbPacket, r smb1ReadRequest) error {
	debug := sess.srv.debug
	start := debug.now()

	bp := readBufPool.Get().(*[]byte)
	defer readBufPool.Put(bp)
	buf := *bp

	const dataStart = frameHeaderSize + smb1ReadDataOffset
	n, ioNs := sess.readFile(buf[dataStart:], r)
	putSMB1ReadHeader(buf, &req.header, n)

	writeStart := debug.now()
	_, err := w.Write(buf[:dataStart+n])
	debug.observe(start, writeStart, ioNs, int64(n))
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// readFile reads the requested range, clamped to what a response and the file can
// hold, into dst. A failed read counts as zero bytes: the client sees a short read.
func (sess *smb1Session) readFile(dst []byte, r smb1ReadRequest) (n int, ioNs int64) {
	share, debug := sess.srv.share, sess.srv.debug

	count := min(r.count, smb1MaxRead)
	if r.offset >= share.Size() {
		count = 0
	} else if r.offset+int64(count) > share.Size() {
		count = int(share.Size() - r.offset)
	}
	if count == 0 {
		return 0, 0
	}

	ioStart := debug.now()
	n, err := share.ReadAt(dst[:count], r.offset)
	ioNs = debug.elapsedNs(ioStart)
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("ReadAt error at offset %d: %v", r.offset, err)
		n = 0
	}
	if n > 0 {
		sess.srv.progress.record(r.offset, n)
	}
	return n, ioNs
}

// putSMB1ReadHeader writes everything in front of the file data to the start of
// buf, which holds stale data from earlier uses.
func putSMB1ReadHeader(buf []byte, reqHeader *smbHeader, n int) {
	putFrameHeader(buf, frameTypeSessionMessage, smb1ReadDataOffset+n)

	smb := buf[frameHeaderSize:]
	h := reqHeader.response()
	h.put(smb)
	smb[smb1HeaderSize] = smb1ReadWordsSize / 2

	words := smb[smb1HeaderSize+1 : smb1HeaderSize+1+smb1ReadWordsSize]
	clear(words)
	words[0] = smbAndXNone
	le.PutUint16(words[4:], 0xFFFF)              // Available
	le.PutUint16(words[10:], uint16(n))          // DataLength
	le.PutUint16(words[12:], smb1ReadDataOffset) // DataOffset

	le.PutUint16(smb[smb1ReadDataOffset-3:], uint16(1+n)) // ByteCount: pad + data
	smb[smb1ReadDataOffset-1] = 0                         // pad
}

// --- LOGOFF_ANDX (0x74) ---

// handleLogoff answers SMB_COM_LOGOFF_ANDX ([MS-CIFS] 2.2.4.54). The session holds
// nothing to release.
func (sess *smb1Session) handleLogoff(req *smbPacket) (*smbPacket, ntStatus) {
	resp := newResponse(req)
	words := make([]byte, 4)
	words[0] = smbAndXNone
	resp.words = words
	return resp, statusOK
}

// --- ECHO (0x2B) ---

// handleEcho answers SMB_COM_ECHO ([MS-CIFS] 2.2.4.39) with one copy of the data.
// The requested EchoCount is ignored.
func (sess *smb1Session) handleEcho(req *smbPacket) (*smbPacket, ntStatus) {
	resp := newResponse(req)
	words := make([]byte, 2)
	le.PutUint16(words, 1) // SequenceNumber
	resp.words = words
	resp.data = req.data
	return resp, statusOK
}
