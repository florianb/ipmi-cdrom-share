package smbserver

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
)

// --- NEGOTIATE ---

func TestChooseSMB2Dialect(t *testing.T) {
	tests := []struct {
		name    string
		offered []uint16
		want    uint16
	}{
		{"bmc", []uint16{0x0302}, 0x0302},
		{"all", []uint16{0x0202, 0x0210, 0x0300, 0x0302, 0x0311}, 0x0210},
		{"202 before 3x", []uint16{0x0302, 0x0300, 0x0202}, 0x0202},
		{"302 before 300", []uint16{0x0300, 0x0302}, 0x0302},
		{"311 only", []uint16{0x0311}, 0},
		{"unknown", []uint16{0x9999}, 0},
		{"none", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := chooseSMB2Dialect(tt.offered); got != tt.want {
				t.Errorf("got %#x, want %#x", got, tt.want)
			}
		})
	}
}

func TestBMCNegotiateSelects302(t *testing.T) {
	frame := bmcNegotiateFrame()
	if len(frame) != 102 {
		t.Fatalf("frame is %d bytes, capture had 102", len(frame))
	}
	srv := newTestServer(t, nil)
	c := dialPipe(t, srv)
	c.sendFrame(frame)
	r := parseResponses(t, c.recvFrame())[0]
	if r.status != statusOK {
		t.Fatalf("status %#x", r.status)
	}
	if d := le.Uint16(r.body[4:]); d != 0x0302 {
		t.Errorf("dialect %#x, want 0x0302", d)
	}
	if size := le.Uint16(r.body[0:]); size != 65 {
		t.Errorf("StructureSize %d", size)
	}
	if !bytes.Equal(r.body[8:24], srv.serverGUID[:]) {
		t.Error("ServerGuid not in response")
	}
	if caps := le.Uint32(r.body[24:]); caps != 0 {
		t.Errorf("Capabilities %#x, want none", caps)
	}
	for _, off := range []int{28, 32, 36} {
		if v := le.Uint32(r.body[off:]); v != maxBufferSize {
			t.Errorf("size field at %d = %d, want 64 KiB", off, v)
		}
	}
	off, n := int(le.Uint16(r.body[56:])), int(le.Uint16(r.body[58:]))
	if !bytes.Equal(r.raw[off:off+n], spnegoInitToken) {
		t.Errorf("security buffer at %d len %d is not the SPNEGO token", off, n)
	}
}

func TestNegotiateFailures(t *testing.T) {
	t.Run("only 3.1.1", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		if r := c.call(smb2Negotiate, negotiateBody(0x0311)); r.status != statusNotSupported {
			t.Errorf("status %#x, want NOT_SUPPORTED", r.status)
		}
		// The connection stays usable for another attempt.
		if r := c.call(smb2Negotiate, negotiateBody(0x0210)); r.status != statusOK {
			t.Errorf("retry status %#x", r.status)
		}
	})
	t.Run("no dialects", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		if r := c.call(smb2Negotiate, negotiateBody()); r.status != statusInvalidParameter {
			t.Errorf("status %#x", r.status)
		}
	})
	t.Run("repeated drops connection", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.call(smb2Negotiate, negotiateBody(0x0210))
		c.sendFrame(encodeRequest(smb2Msg{command: smb2Negotiate, body: negotiateBody(0x0210)}))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
	t.Run("command before negotiate drops connection", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.sendFrame(encodeRequest(smb2Msg{command: smb2Echo, body: []byte{4, 0, 0, 0}}))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
}

func TestWildcardRenegotiates(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.sendFrame(smb1Negotiate("SMB 2.???"))
	c.recvFrame()
	c.nextID = 1
	c.connect(0x0202, 0x0210, 0x0300)
	id := c.open(testFileName)
	if r := c.call(smb2Read, readBody(id, 0, 10, 0)); r.status != statusOK {
		t.Errorf("READ status %#x", r.status)
	}
}

// --- NTLM ---

func TestParseNTLMToken(t *testing.T) {
	negotiate := ntlmMessage(ntlmMessageNegotiate)
	tests := []struct {
		name       string
		blob       []byte
		wantType   uint32
		wantSPNEGO bool
		wantErr    bool
	}{
		{"raw negotiate", negotiate, ntlmMessageNegotiate, false, false},
		{"raw authenticate", ntlmMessage(ntlmMessageAuthenticate), ntlmMessageAuthenticate, false, false},
		{"wrapped", spnegoChallenge(negotiate), ntlmMessageNegotiate, true, false},
		{"empty", nil, 0, false, true},
		{"kerberos only", []byte{0x60, 0x03, 0x06, 0x01, 0x2A}, 0, false, true},
		{"truncated", []byte("NTLMSSP\x00\x01"), 0, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok, err := parseNTLMToken(tt.blob)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v", err)
			}
			if tok.messageType != tt.wantType || tok.spnego != tt.wantSPNEGO {
				t.Errorf("token %+v", tok)
			}
		})
	}
}

func TestNTLMChallengeFormat(t *testing.T) {
	const clientFlags = 0x80000010 | 0x00080000
	msg, err := buildNTLMChallenge(clientFlags)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, ntlmSignature) || le.Uint32(msg[8:]) != ntlmMessageChallenge {
		t.Fatalf("bad header: % x", msg[:12])
	}
	flags := le.Uint32(msg[20:])
	if flags&clientFlags != clientFlags {
		t.Errorf("flags %#x do not echo client flags", flags)
	}
	if flags&0x40000000 != 0 {
		t.Errorf("flags %#x grant KEY_EXCH the client did not request", flags)
	}

	nameLen, nameOff := int(le.Uint16(msg[12:])), int(le.Uint32(msg[16:]))
	if got := decodeUTF16LE(msg[nameOff : nameOff+nameLen]); got != ntlmTargetName {
		t.Errorf("target name %q", got)
	}
	infoLen, infoOff := int(le.Uint16(msg[40:])), int(le.Uint32(msg[44:]))
	info := msg[infoOff : infoOff+infoLen]
	seen := map[uint16]bool{}
	for {
		id, n := le.Uint16(info), int(le.Uint16(info[2:]))
		seen[id] = true
		info = info[4+n:]
		if id == ntlmAvEOL {
			break
		}
	}
	if len(info) != 0 || !seen[ntlmAvNbComputerName] || !seen[ntlmAvNbDomainName] || seen[7] {
		t.Errorf("target info: seen %v, %d bytes left", seen, len(info))
	}
}

func TestSessionSetupFlow(t *testing.T) {
	for _, tt := range []struct {
		name   string
		spnego bool
	}{{"raw", false}, {"spnego", true}} {
		t.Run(tt.name, func(t *testing.T) {
			wrap := func(m []byte) []byte {
				if tt.spnego {
					return derTLV(derContext1, derTLV(derOctetString, m))
				}
				return m
			}
			c := dialPipe(t, newTestServer(t, nil))
			c.call(smb2Negotiate, negotiateBody(0x0302))

			r := c.call(smb2SessionSetup, sessionSetupBody(wrap(ntlmMessage(ntlmMessageNegotiate))))
			if r.status != statusMoreProcessingRequired || r.sessionID == 0 {
				t.Fatalf("step 1: status %#x session %d", r.status, r.sessionID)
			}
			off, n := int(le.Uint16(r.body[4:])), int(le.Uint16(r.body[6:]))
			blob := r.raw[off : off+n]
			if tok, err := parseNTLMToken(blob); err != nil || tok.messageType != ntlmMessageChallenge || tok.spnego != tt.spnego {
				t.Fatalf("step 1 token %+v, err %v", tok, err)
			}

			// The session must not be usable before AUTHENTICATE.
			c.sess = r.sessionID
			if r := c.call(smb2TreeConnect, treeConnectBody(`\\h\s`)); r.status != statusUserSessionDeleted {
				t.Errorf("tree connect before auth: status %#x", r.status)
			}

			r = c.call(smb2SessionSetup, sessionSetupBody(wrap(ntlmMessage(ntlmMessageAuthenticate))))
			if r.status != statusOK {
				t.Fatalf("step 2: status %#x", r.status)
			}
			if flags := le.Uint16(r.body[2:]); flags != smb2SessionFlagIsGuest {
				t.Errorf("session flags %#x, want guest", flags)
			}
			hasBlob := le.Uint16(r.body[6:]) != 0
			if hasBlob != tt.spnego {
				t.Errorf("final blob present = %v", hasBlob)
			}
		})
	}
}

func TestSessionSetupFailures(t *testing.T) {
	tests := []struct {
		name    string
		session uint64
		blob    []byte
		want    ntStatus
	}{
		{"authenticate without negotiate", 0, ntlmMessage(ntlmMessageAuthenticate), statusLogonFailure},
		{"unknown session", 99, ntlmMessage(ntlmMessageNegotiate), statusUserSessionDeleted},
		{"no token", 0, []byte{1, 2, 3}, statusLogonFailure},
		{"bad message type", 0, ntlmMessage(9), statusLogonFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, nil))
			c.call(smb2Negotiate, negotiateBody(0x0302))
			c.sess = tt.session
			if r := c.call(smb2SessionSetup, sessionSetupBody(tt.blob)); r.status != tt.want {
				t.Errorf("status %#x, want %#x", r.status, tt.want)
			}
		})
	}
}

// --- Tree and handle scope ---

func TestTreeConnectShareTypes(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.connect(0x0302)
	for _, tt := range []struct {
		unc  string
		want byte
	}{
		{`\\h\IPC$`, smb2ShareTypePipe},
		{`\\h\ipc$`, smb2ShareTypePipe},
		{`\\h\share`, smb2ShareTypeDisk},
		{`\\h\whatever`, smb2ShareTypeDisk},
	} {
		r := c.call(smb2TreeConnect, treeConnectBody(tt.unc))
		if r.status != statusOK || r.body[2] != tt.want {
			t.Errorf("%s: status %#x type %d", tt.unc, r.status, r.body[2])
		}
	}
}

func TestRequiresSessionAndTree(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.call(smb2Negotiate, negotiateBody(0x0210))
	if r := c.call(smb2Create, createBody("x", 1, fileOpen, 0)); r.status != statusUserSessionDeleted {
		t.Errorf("no session: status %#x", r.status)
	}
	c.connect2Session()
	if r := c.call(smb2Create, createBody("x", 1, fileOpen, 0)); r.status != statusNetworkNameDeleted {
		t.Errorf("no tree: status %#x", r.status)
	}
}

func TestTreeDisconnectAndLogoffCloseHandles(t *testing.T) {
	t.Run("tree disconnect", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, testContent(10)))
		c.connect(0x0302)
		c.open(testFileName)
		if r := c.call(smb2TreeDisconnect, []byte{4, 0, 0, 0}); r.status != statusOK {
			t.Fatalf("status %#x", r.status)
		}
		if r := c.call(smb2Read, readBody(make([]byte, 16), 0, 1, 0)); r.status != statusNetworkNameDeleted {
			t.Errorf("read: status %#x", r.status)
		}
	})
	t.Run("logoff", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, testContent(10)))
		c.connect(0x0302)
		c.open(testFileName)
		if r := c.call(smb2Logoff, []byte{4, 0, 0, 0}); r.status != statusOK {
			t.Fatalf("status %#x", r.status)
		}
		if r := c.call(smb2Echo, []byte{4, 0, 0, 0}); r.status != statusOK {
			t.Errorf("echo after logoff: status %#x", r.status)
		}
		if r := c.call(smb2TreeConnect, treeConnectBody(`\\h\s`)); r.status != statusUserSessionDeleted {
			t.Errorf("tree connect after logoff: status %#x", r.status)
		}
	})
}

// --- CREATE ---

func TestCreate(t *testing.T) {
	const genericWrite = 0x40000000
	const readAttrs = 0x00000080
	tests := []struct {
		name        string
		path        string
		access      uint32
		disposition uint32
		options     uint32
		want        ntStatus
	}{
		{"file", testFileName, readAttrs, fileOpen, 0, statusOK},
		{"case insensitive", "TEST.ISO", readAttrs, fileOpen, 0, statusOK},
		{"leading backslash", `\Test.iso`, readAttrs, fileOpen, 0, statusOK},
		{"open if", testFileName, readAttrs, fileOpenIf, 0, statusOK},
		{"root", "", readAttrs, fileOpen, createDirectoryFile, statusOK},
		{"missing", "other.iso", readAttrs, fileOpen, 0, statusObjectNameNotFound},
		{"create missing", "other.iso", readAttrs, fileCreate, 0, statusAccessDenied},
		{"create existing", testFileName, readAttrs, fileCreate, 0, statusObjectNameCollision},
		{"overwrite", testFileName, readAttrs, 4, 0, statusAccessDenied},
		{"write access", testFileName, genericWrite, fileOpen, 0, statusAccessDenied},
		{"write data", testFileName, 0x2, fileOpen, 0, statusAccessDenied},
		{"delete on close", testFileName, readAttrs, fileOpen, createDeleteOnClose, statusAccessDenied},
		{"file as directory", testFileName, readAttrs, fileOpen, createDirectoryFile, statusNotADirectory},
		{"root as file", "", readAttrs, fileOpen, createNonDirectoryFile, statusFileIsADirectory},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, testContent(5000)))
			c.connect(0x0302)
			r := c.call(smb2Create, createBody(tt.path, tt.access, tt.disposition, tt.options))
			if r.status != tt.want {
				t.Fatalf("status %#x, want %#x", r.status, tt.want)
			}
			if r.status != statusOK {
				if len(r.body) != 9 || r.body[0] != 9 {
					t.Errorf("error body % x", r.body)
				}
				return
			}
			if size := le.Uint16(r.body); size != 89 {
				t.Errorf("StructureSize %d", size)
			}
			isDir := tt.path == ""
			wantEOF, wantAttr := uint64(5000), uint32(fileAttrReadOnly)
			if isDir {
				wantEOF, wantAttr = 0, fileAttrDirectory
			}
			if eof := le.Uint64(r.body[48:]); eof != wantEOF {
				t.Errorf("EndOfFile %d, want %d", eof, wantEOF)
			}
			if attr := le.Uint32(r.body[56:]); attr != wantAttr {
				t.Errorf("attributes %#x, want %#x", attr, wantAttr)
			}
		})
	}
}

func TestCreateContextsIgnored(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	body := createBody(testFileName, 0x80, fileOpen, 0)
	le.PutUint32(body[48:], smb2HeaderSize+uint32(len(body)))
	le.PutUint32(body[52:], 16)
	body = append(body, make([]byte, 16)...)
	r := c.call(smb2Create, body)
	if r.status != statusOK {
		t.Fatalf("status %#x", r.status)
	}
	if off, n := le.Uint32(r.body[80:]), le.Uint32(r.body[84:]); off != 0 || n != 0 {
		t.Errorf("response contexts offset %d length %d", off, n)
	}
}

func TestCreateOnPipeShareNotFound(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	r := c.call(smb2TreeConnect, treeConnectBody(`\\h\IPC$`))
	c.tree = r.treeID
	if r := c.call(smb2Create, createBody("srvsvc", 0x80, fileOpen, 0)); r.status != statusObjectNameNotFound {
		t.Errorf("status %#x", r.status)
	}
}

// --- READ ---

func TestReadBoundaries(t *testing.T) {
	const size = 2*maxBufferSize + 100
	content := testContent(size)
	tests := []struct {
		name     string
		offset   uint64
		length   uint32
		minimum  uint32
		want     ntStatus
		wantData int
	}{
		{"start", 0, 100, 0, statusOK, 100},
		{"full 64k", 0, maxBufferSize, 0, statusOK, maxBufferSize},
		{"too large", 0, maxBufferSize + 1, 0, statusInvalidParameter, 0},
		{"short at end", size - 10, 100, 0, statusOK, 10},
		{"last byte", size - 1, 1, 0, statusOK, 1},
		{"at eof", size, 1, 0, statusEndOfFile, 0},
		{"past eof", size + 100, 1, 0, statusEndOfFile, 0},
		{"huge offset", ^uint64(0), 1, 0, statusEndOfFile, 0},
		{"minimum not met", size - 10, 100, 11, statusEndOfFile, 0},
		{"minimum met", size - 10, 100, 10, statusOK, 10},
		{"zero length", 5, 0, 0, statusOK, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, content))
			c.connect(0x0302)
			id := c.open(testFileName)
			r := c.call(smb2Read, readBody(id, tt.offset, tt.length, tt.minimum))
			if r.status != tt.want {
				t.Fatalf("status %#x, want %#x", r.status, tt.want)
			}
			if tt.want != statusOK {
				return
			}
			off, n := int(r.body[2]), int(le.Uint32(r.body[4:]))
			if off != 80 || n != tt.wantData {
				t.Fatalf("offset %d length %d, want 80, %d", off, n, tt.wantData)
			}
			if !bytes.Equal(r.raw[off:off+n], content[tt.offset:tt.offset+uint64(n)]) {
				t.Error("data mismatch")
			}
		})
	}
}

func TestReadHandleErrors(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	if r := c.call(smb2Read, readBody(make([]byte, 16), 0, 1, 0)); r.status != statusFileClosed {
		t.Errorf("unknown handle: status %#x", r.status)
	}
	root := c.open("")
	if r := c.call(smb2Read, readBody(root, 0, 1, 0)); r.status != statusInvalidDeviceRequest {
		t.Errorf("directory: status %#x", r.status)
	}
}

func TestClose(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	id := c.open(testFileName)
	r := c.call(smb2Close, closeBody(id))
	if r.status != statusOK {
		t.Fatalf("status %#x", r.status)
	}
	if size, eof := le.Uint16(r.body), le.Uint64(r.body[48:]); size != 60 || eof != 10 {
		t.Errorf("StructureSize %d EndOfFile %d", size, eof)
	}
	if r := c.call(smb2Close, closeBody(id)); r.status != statusFileClosed {
		t.Errorf("second close: status %#x", r.status)
	}
	if r := c.call(smb2Read, readBody(id, 0, 1, 0)); r.status != statusFileClosed {
		t.Errorf("read after close: status %#x", r.status)
	}
}

// --- Compound requests ---

func TestCompoundCreateQueryClose(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(1234)))
	c.connect(0x0302)
	placeholder := bytes.Repeat([]byte{0xFF}, 16)

	frame := alignCompound(
		encodeRequest(smb2Msg{command: smb2Create, messageID: 100, sessionID: c.sess, treeID: c.tree,
			body: createBody(testFileName, 0x80, fileOpen, 0)}),
		encodeRequest(smb2Msg{command: smb2QueryInfo, messageID: 101, flags: smb2FlagRelated,
			sessionID: smb2AllOnes, treeID: ^uint32(0),
			body: queryInfoBody(placeholder, infoTypeFile, fileStandardInformation, 64)}),
		encodeRequest(smb2Msg{command: smb2Close, messageID: 102, flags: smb2FlagRelated,
			sessionID: smb2AllOnes, treeID: ^uint32(0),
			body: closeBody(placeholder)}),
	)
	c.sendFrame(frame)
	rs := parseResponses(t, c.recvFrame())
	if len(rs) != 3 {
		t.Fatalf("got %d responses", len(rs))
	}
	for i, r := range rs {
		if r.status != statusOK {
			t.Errorf("response %d: status %#x", i, r.status)
		}
		if r.messageID != uint64(100+i) {
			t.Errorf("response %d: mid %d", i, r.messageID)
		}
		if r.sessionID != c.sess || r.treeID != c.tree {
			t.Errorf("response %d: session %d tree %d not resolved", i, r.sessionID, r.treeID)
		}
		if related := r.flags&smb2FlagRelated != 0; related != (i > 0) {
			t.Errorf("response %d: related = %v", i, related)
		}
	}
	if rs[2].next != 0 {
		t.Errorf("last NextCommand %d", rs[2].next)
	}
	if eof := le.Uint64(rs[1].body[8+8:]); eof != 1234 {
		t.Errorf("EndOfFile %d", eof)
	}
}

func TestCompoundFailedCreateFailsRelated(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	placeholder := bytes.Repeat([]byte{0xFF}, 16)
	c.sendFrame(alignCompound(
		encodeRequest(smb2Msg{command: smb2Create, sessionID: c.sess, treeID: c.tree,
			body: createBody("missing", 0x80, fileOpen, 0)}),
		encodeRequest(smb2Msg{command: smb2QueryInfo, messageID: 1, flags: smb2FlagRelated,
			body: queryInfoBody(placeholder, infoTypeFile, fileStandardInformation, 64)}),
		encodeRequest(smb2Msg{command: smb2Close, messageID: 2, flags: smb2FlagRelated, body: closeBody(placeholder)}),
	))
	for i, r := range parseResponses(t, c.recvFrame()) {
		if r.status != statusObjectNameNotFound {
			t.Errorf("response %d: status %#x", i, r.status)
		}
	}
}

func TestCompoundFirstRelatedRejected(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.connect(0x0302)
	c.sendFrame(encodeRequest(smb2Msg{command: smb2Echo, flags: smb2FlagRelated, body: []byte{4, 0, 0, 0}}))
	if r := parseResponses(t, c.recvFrame())[0]; r.status != statusInvalidParameter {
		t.Errorf("status %#x", r.status)
	}
}

func TestCompoundResponseIsBounded(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(maxBufferSize)))
	c.connect(0x0302)
	id := c.open(testFileName)
	var msgs [][]byte
	const reads = 64 // 4 MiB of data if all were served
	for i := 0; i < reads; i++ {
		msgs = append(msgs, encodeRequest(smb2Msg{command: smb2Read, messageID: uint64(10 + i),
			sessionID: c.sess, treeID: c.tree, body: readBody(id, 0, maxBufferSize, 0)}))
	}
	c.sendFrame(alignCompound(msgs...))
	frame := c.recvFrame()
	if len(frame) > smb2MaxCompoundResponse+2*maxBufferSize {
		t.Errorf("response of %d bytes", len(frame))
	}
	rs := parseResponses(t, frame)
	if len(rs) != reads {
		t.Fatalf("got %d responses", len(rs))
	}
	if rs[0].status != statusOK || rs[reads-1].status != statusInsufficientResources {
		t.Errorf("first status %#x, last %#x", rs[0].status, rs[reads-1].status)
	}
}

func TestMalformedCompoundDropsConnection(t *testing.T) {
	for _, tt := range []struct {
		name string
		next uint32
	}{{"short", 8}, {"unaligned", 65}, {"past end", 1 << 20}} {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, nil))
			c.connect(0x0302)
			c.sendFrame(encodeRequest(smb2Msg{command: smb2Echo, next: tt.next, body: []byte{4, 0, 0, 0}}))
			if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
				t.Errorf("read: %v, want EOF", err)
			}
		})
	}
}

func TestCreditsAndCancel(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.connect(0x0302)

	for _, tt := range []struct{ request, want uint16 }{{0, 1}, {1, 1}, {50, 50}, {1000, smb2MaxCredits}} {
		c.sendFrame(encodeRequest(smb2Msg{command: smb2Echo, credits: tt.request, body: []byte{4, 0, 0, 0}}))
		if r := parseResponses(t, c.recvFrame())[0]; r.credits != tt.want {
			t.Errorf("request %d: granted %d, want %d", tt.request, r.credits, tt.want)
		}
	}

	// CANCEL has no response: the next frame read must answer the ECHO.
	c.sendFrame(encodeRequest(smb2Msg{command: smb2Cancel, messageID: 500, body: []byte{4, 0, 0, 0}}))
	c.sendFrame(encodeRequest(smb2Msg{command: smb2Echo, messageID: 501, body: []byte{4, 0, 0, 0}}))
	if r := parseResponses(t, c.recvFrame())[0]; r.messageID != 501 {
		t.Errorf("got response to mid %d", r.messageID)
	}
}

// --- QUERY_INFO ---

func TestQueryInfoClasses(t *testing.T) {
	tests := []struct {
		name     string
		infoType byte
		class    byte
		wantLen  int
	}{
		{"basic", infoTypeFile, fileBasicInformation, 40},
		{"standard", infoTypeFile, fileStandardInformation, 24},
		{"internal", infoTypeFile, fileInternalInformation, 8},
		{"ea", infoTypeFile, fileEaInformation, 4},
		{"access", infoTypeFile, fileAccessInformation, 4},
		{"position", infoTypeFile, filePositionInformation, 8},
		{"mode", infoTypeFile, fileModeInformation, 4},
		{"alignment", infoTypeFile, fileAlignmentInformation, 4},
		{"all", infoTypeFile, fileAllInformation, 100 + 2*(len(testFileName)+1)},
		{"network open", infoTypeFile, fileNetworkOpenInformation, 56},
		{"attribute tag", infoTypeFile, fileAttributeTagInformation, 8},
		{"fs volume", infoTypeFilesystem, fileFsVolumeInformation, 18 + 2*len(volumeLabel)},
		{"fs size", infoTypeFilesystem, fileFsSizeInformation, 24},
		{"fs device", infoTypeFilesystem, fileFsDeviceInformation, 8},
		{"fs attribute", infoTypeFilesystem, fileFsAttributeInformation, 12 + 2*len(fsAttributeName)},
		{"fs full size", infoTypeFilesystem, fileFsFullSizeInformation, 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, testContent(5000)))
			c.connect(0x0302)
			id := c.open(testFileName)
			r := c.call(smb2QueryInfo, queryInfoBody(id, tt.infoType, tt.class, 4096))
			if r.status != statusOK {
				t.Fatalf("status %#x", r.status)
			}
			off, n := int(le.Uint16(r.body[2:])), int(le.Uint32(r.body[4:]))
			if off != 72 || n != tt.wantLen || off+n != len(r.raw) {
				t.Errorf("offset %d length %d of %d, want length %d", off, n, len(r.raw), tt.wantLen)
			}
		})
	}
}

func TestQueryInfoValues(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(5000)))
	c.connect(0x0302)
	id := c.open(testFileName)
	data := func(class byte) []byte {
		r := c.call(smb2QueryInfo, queryInfoBody(id, infoTypeFile, class, 4096))
		return r.raw[72:]
	}

	std := data(fileStandardInformation)
	if alloc, eof := le.Uint64(std), le.Uint64(std[8:]); alloc != 8192 || eof != 5000 {
		t.Errorf("standard: allocation %d, end of file %d", alloc, eof)
	}
	all := data(fileAllInformation)
	if eof := le.Uint64(all[48:]); eof != 5000 {
		t.Errorf("all: end of file %d", eof)
	}
	if got := decodeUTF16LE(all[100:]); got != `\`+testFileName {
		t.Errorf("all: name %q", got)
	}
	netOpen := data(fileNetworkOpenInformation)
	if eof, attr := le.Uint64(netOpen[40:]), le.Uint32(netOpen[48:]); eof != 5000 || attr != fileAttrReadOnly {
		t.Errorf("network open: end of file %d, attributes %#x", eof, attr)
	}
}

func TestQueryInfoErrors(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	id := c.open(testFileName)
	tests := []struct {
		name string
		body []byte
		want ntStatus
	}{
		{"unknown class", queryInfoBody(id, infoTypeFile, 99, 4096), statusInvalidInfoClass},
		{"unknown fs class", queryInfoBody(id, infoTypeFilesystem, 99, 4096), statusInvalidInfoClass},
		{"security", queryInfoBody(id, 3, 0, 4096), statusNotSupported},
		{"fixed too small", queryInfoBody(id, infoTypeFile, fileBasicInformation, 39), statusInfoLengthMismatch},
		{"all truncated", queryInfoBody(id, infoTypeFile, fileAllInformation, 102), statusBufferOverflow},
		{"bad handle", queryInfoBody(make([]byte, 16), infoTypeFile, fileBasicInformation, 40), statusFileClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := c.call(smb2QueryInfo, tt.body); r.status != tt.want {
				t.Errorf("status %#x, want %#x", r.status, tt.want)
			}
		})
	}
}

// --- QUERY_DIRECTORY ---

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		pattern string
		want    bool
	}{
		{"", true},
		{"*", true},
		{"*.*", true},
		{"test.iso", true},
		{"TEST.ISO", true},
		{"*.iso", true},
		{"t*o", true},
		{"T?st.iso", true},
		{"<.iso", true},
		{`test"iso`, true},
		{"test.is>", true},
		{"te*st*", true},
		{"*.img", false},
		{"test", false},
		{"test.iso.bak", false},
		{"?", false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern, func(t *testing.T) {
			if got := matchPattern(tt.pattern, testFileName); got != tt.want {
				t.Errorf("got %v", got)
			}
		})
	}
}

func TestQueryDirectory(t *testing.T) {
	for _, tt := range []struct {
		name       string
		class      byte
		nameOffset int
	}{
		{"directory", fileDirectoryInformation, 64},
		{"full", fileFullDirectoryInformation, 68},
		{"both", fileBothDirectoryInformation, 94},
		{"names", fileNamesInformation, 12},
		{"id full", fileIDFullDirInformation, 80},
		{"id both", fileIDBothDirInformation, 104},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, testContent(5000)))
			c.connect(0x0302)
			root := c.open("")

			r := c.call(smb2QueryDirectory, queryDirBody(root, tt.class, 0, "*", 4096))
			if r.status != statusOK {
				t.Fatalf("status %#x", r.status)
			}
			entry := r.raw[le.Uint16(r.body[2:]):]
			if got := decodeUTF16LE(entry[tt.nameOffset:]); got != testFileName {
				t.Errorf("name %q", got)
			}
			if tt.class != fileNamesInformation {
				if eof := le.Uint64(entry[40:]); eof != 5000 {
					t.Errorf("end of file %d", eof)
				}
				if n := le.Uint32(entry[60:]); int(n) != 2*len(testFileName) {
					t.Errorf("name length %d", n)
				}
			}

			r = c.call(smb2QueryDirectory, queryDirBody(root, tt.class, 0, "*", 4096))
			if r.status != statusNoMoreFiles {
				t.Errorf("second query: status %#x", r.status)
			}
			r = c.call(smb2QueryDirectory, queryDirBody(root, tt.class, queryDirRestartScans, "*", 4096))
			if r.status != statusOK {
				t.Errorf("restart: status %#x", r.status)
			}
		})
	}
}

func TestQueryDirectoryErrors(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	root := c.open("")
	file := c.open(testFileName)
	tests := []struct {
		name string
		body []byte
		want ntStatus
	}{
		{"pattern mismatch", queryDirBody(root, fileDirectoryInformation, 0, "*.img", 4096), statusNoSuchFile},
		{"unknown class", queryDirBody(root, 99, 0, "*", 4096), statusInvalidInfoClass},
		{"buffer too small", queryDirBody(root, fileDirectoryInformation, 0, "*", 10), statusBufferTooSmall},
		{"not a directory", queryDirBody(file, fileDirectoryInformation, 0, "*", 4096), statusInvalidParameter},
		{"bad handle", queryDirBody(make([]byte, 16), fileDirectoryInformation, 0, "*", 4096), statusFileClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r := c.call(smb2QueryDirectory, tt.body); r.status != tt.want {
				t.Errorf("status %#x, want %#x", r.status, tt.want)
			}
		})
	}
}

// --- IOCTL ---

func TestValidateNegotiate(t *testing.T) {
	srv := newTestServer(t, nil)
	c := dialPipe(t, srv)
	c.connect(0x0302)
	r := c.call(smb2Ioctl, ioctlBody(fsctlValidateNegotiateInfo, validateNegotiateInput(7, 1, 0x0302), 24))
	if r.status != statusOK {
		t.Fatalf("status %#x", r.status)
	}
	off, n := int(le.Uint32(r.body[32:])), int(le.Uint32(r.body[36:]))
	if n != 24 || off+n != len(r.raw) {
		t.Fatalf("output offset %d length %d of %d", off, n, len(r.raw))
	}
	info := r.raw[off:]
	if caps := le.Uint32(info); caps != 0 {
		t.Errorf("capabilities %#x", caps)
	}
	if !bytes.Equal(info[4:20], srv.serverGUID[:]) {
		t.Error("server GUID differs from NEGOTIATE")
	}
	if mode, dialect := le.Uint16(info[20:]), le.Uint16(info[22:]); mode != 1 || dialect != 0x0302 {
		t.Errorf("security mode %#x dialect %#x", mode, dialect)
	}
}

func TestValidateNegotiateMismatchDropsConnection(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"capabilities", validateNegotiateInput(0, 1, 0x0302)},
		{"security mode", validateNegotiateInput(7, 0, 0x0302)},
		{"dialects", validateNegotiateInput(7, 1, 0x0302, 0x0210)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, nil))
			c.connect(0x0302)
			c.sendFrame(encodeRequest(smb2Msg{command: smb2Ioctl, sessionID: c.sess, treeID: c.tree,
				body: ioctlBody(fsctlValidateNegotiateInfo, tt.input, 24)}))
			if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
				t.Errorf("read: %v, want EOF", err)
			}
		})
	}
}

func TestIoctlUnsupported(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.connect(0x0302)
	if r := c.call(smb2Ioctl, ioctlBody(fsctlDFSGetReferrals, nil, 4096)); r.status != statusFSDriverRequired {
		t.Errorf("DFS: status %#x", r.status)
	}
	if r := c.call(smb2Ioctl, ioctlBody(0x12345678, nil, 4096)); r.status != statusNotSupported {
		t.Errorf("other: status %#x", r.status)
	}
	if r := c.call(smb2Ioctl, ioctlBody(fsctlValidateNegotiateInfo, []byte{1, 2}, 24)); r.status != statusInvalidParameter {
		t.Errorf("short input: status %#x", r.status)
	}
}

func TestRejectedCommandsKeepConnection(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	for _, tt := range []struct {
		command uint16
		want    ntStatus
	}{
		{smb2Write, statusAccessDenied},
		{smb2SetInfo, statusAccessDenied},
		{smb2Flush, statusAccessDenied},
		{smb2Lock, statusNotSupported},
		{smb2ChangeNotify, statusNotSupported},
		{smb2OplockBreak, statusNotSupported},
		{0x77, statusInvalidParameter},
	} {
		if r := c.call(tt.command, []byte{4, 0, 0, 0}); r.status != tt.want {
			t.Errorf("command %#x: status %#x, want %#x", tt.command, r.status, tt.want)
		}
	}
	if r := c.call(smb2Echo, []byte{4, 0, 0, 0}); r.status != statusOK {
		t.Errorf("echo: status %#x", r.status)
	}
}

func TestBadStructureSize(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	if r := c.call(smb2Read, []byte{1, 2, 3}); r.status != statusInvalidParameter {
		t.Errorf("truncated body: status %#x", r.status)
	}
	body := readBody(make([]byte, 16), 0, 1, 0)
	le.PutUint16(body, 48)
	if r := c.call(smb2Read, body); r.status != statusInvalidParameter {
		t.Errorf("wrong size: status %#x", r.status)
	}
}

func TestHandleLimit(t *testing.T) {
	c := dialPipe(t, newTestServer(t, testContent(10)))
	c.connect(0x0302)
	for i := 0; i < smb2MaxHandles; i++ {
		c.open(testFileName)
	}
	if r := c.call(smb2Create, createBody(testFileName, 0x80, fileOpen, 0)); r.status != statusInsufficientResources {
		t.Errorf("status %#x", r.status)
	}
}

// --- End to end ---

// TestE2ESMB2 downloads the whole file over each dialect, the way a client does.
func TestE2ESMB2(t *testing.T) {
	content := testContent(3*maxBufferSize + 1234)
	for _, dialect := range []uint16{0x0202, 0x0210, 0x0300, 0x0302} {
		t.Run(fmt.Sprintf("%#04x", dialect), func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, content))
			c.connect(dialect)

			root := c.open("")
			r := c.call(smb2QueryDirectory, queryDirBody(root, fileIDBothDirInformation, 0, "*", 65536))
			if r.status != statusOK {
				t.Fatalf("list: status %#x", r.status)
			}
			if r := c.call(smb2Close, closeBody(root)); r.status != statusOK {
				t.Fatalf("close root: status %#x", r.status)
			}

			id := c.open(testFileName)
			var got []byte
			for {
				r := c.call(smb2Read, readBody(id, uint64(len(got)), maxBufferSize, 0))
				if r.status == statusEndOfFile {
					break
				}
				if r.status != statusOK {
					t.Fatalf("read at %d: status %#x", len(got), r.status)
				}
				got = append(got, r.raw[r.body[2]:]...)
			}
			if !bytes.Equal(got, content) {
				t.Errorf("downloaded %d bytes, content differs (want %d)", len(got), len(content))
			}
			for _, step := range []struct {
				command uint16
				body    []byte
			}{
				{smb2Close, closeBody(id)},
				{smb2TreeDisconnect, []byte{4, 0, 0, 0}},
				{smb2Logoff, []byte{4, 0, 0, 0}},
			} {
				if r := c.call(step.command, step.body); r.status != statusOK {
					t.Errorf("command %#x: status %#x", step.command, r.status)
				}
			}
		})
	}
}

// BenchmarkSMB2Read measures the allocation-free read path.
func BenchmarkSMB2Read(b *testing.B) {
	srv := newTestServer(b, testContent(maxBufferSize))
	c := newSMB2Conn(srv, "bench")
	c.dialect = smb2Dialect302
	c.sessions[1] = &smb2Session{authenticated: true, trees: map[uint32]*smb2Tree{1: {}}}
	c.handles[1] = &smb2Handle{id: smb2FileID{1, 1}, sessionID: 1, treeID: 1}
	id := make([]byte, 16)
	le.PutUint64(id, 1)
	le.PutUint64(id[8:], 1)
	frame := encodeRequest(smb2Msg{command: smb2Read, sessionID: 1, treeID: 1, body: readBody(id, 0, maxBufferSize, 0)})
	b.SetBytes(maxBufferSize)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if err := c.serveFrame(io.Discard, frame); err != nil {
			b.Fatal(err)
		}
	}
}
