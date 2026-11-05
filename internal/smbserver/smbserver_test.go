package smbserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testFileName = "Test.iso"

// testContent returns deterministic data of a size that needs several 64 KiB reads.
func testContent(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i*7 + i>>8)
	}
	return b
}

func newTestServer(t testing.TB, content []byte) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), testFileName)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	share, err := OpenShare(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { share.Close() })
	srv, err := NewServer(share, false)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// --- SMB2 test client ---

// smb2Msg is a request to send or a parsed response.
type smb2Msg struct {
	command   uint16
	status    uint32
	flags     uint32
	next      uint32
	messageID uint64
	treeID    uint32
	sessionID uint64
	credits   uint16
	body      []byte
	raw       []byte // whole message, for offsets relative to its start
}

func encodeRequest(m smb2Msg) []byte {
	b := make([]byte, smb2HeaderSize, smb2HeaderSize+len(m.body))
	copy(b, "\xFESMB")
	le.PutUint16(b[4:], smb2HeaderSize)
	le.PutUint16(b[6:], 1) // CreditCharge
	le.PutUint16(b[12:], m.command)
	le.PutUint16(b[14:], m.credits)
	le.PutUint32(b[16:], m.flags)
	le.PutUint32(b[20:], m.next)
	le.PutUint64(b[24:], m.messageID)
	le.PutUint32(b[36:], m.treeID)
	le.PutUint64(b[40:], m.sessionID)
	return append(b, m.body...)
}

func parseResponses(t testing.TB, frame []byte) []smb2Msg {
	t.Helper()
	var out []smb2Msg
	for {
		if len(frame) < smb2HeaderSize || string(frame[:4]) != "\xFESMB" {
			t.Fatalf("bad SMB2 response: % x", frame[:min(len(frame), 16)])
		}
		m := smb2Msg{
			status:    le.Uint32(frame[8:]),
			command:   le.Uint16(frame[12:]),
			credits:   le.Uint16(frame[14:]),
			flags:     le.Uint32(frame[16:]),
			next:      le.Uint32(frame[20:]),
			messageID: le.Uint64(frame[24:]),
			treeID:    le.Uint32(frame[36:]),
			sessionID: le.Uint64(frame[40:]),
		}
		if m.flags&smb2FlagServerToRedir == 0 {
			t.Errorf("response without SERVER_TO_REDIR: flags %#x", m.flags)
		}
		end := len(frame)
		if m.next != 0 {
			if m.next%8 != 0 {
				t.Errorf("NextCommand %d not 8-byte aligned", m.next)
			}
			end = int(m.next)
		}
		m.raw = frame[:end]
		m.body = frame[smb2HeaderSize:end]
		out = append(out, m)
		if m.next == 0 {
			return out
		}
		frame = frame[end:]
	}
}

type testClient struct {
	t      testing.TB
	conn   net.Conn
	nextID uint64
	sess   uint64
	tree   uint32
}

// dialPipe connects a client to srv over net.Pipe and stops the handler at cleanup.
func dialPipe(t testing.TB, srv *Server) *testClient {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.handleConn(ctx, server)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		<-done
	})
	if err := client.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return &testClient{t: t, conn: client}
}

func (c *testClient) sendFrame(payload []byte) {
	c.t.Helper()
	if err := writeFrame(c.conn, frameTypeSessionMessage, payload); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

func (c *testClient) recvFrame() []byte {
	c.t.Helper()
	frame, msgType, err := readFrame(c.conn)
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	if msgType != frameTypeSessionMessage {
		c.t.Fatalf("frame type %#x", msgType)
	}
	return frame
}

// call sends one request and returns its response.
func (c *testClient) call(command uint16, body []byte) smb2Msg {
	c.t.Helper()
	id := c.nextID
	c.nextID++
	c.sendFrame(encodeRequest(smb2Msg{command: command, messageID: id, sessionID: c.sess, treeID: c.tree, body: body}))
	rs := parseResponses(c.t, c.recvFrame())
	if len(rs) != 1 {
		c.t.Fatalf("got %d responses", len(rs))
	}
	if rs[0].messageID != id || rs[0].command != command {
		c.t.Fatalf("response mid=%d cmd=%d for mid=%d cmd=%d", rs[0].messageID, rs[0].command, id, command)
	}
	return rs[0]
}

func negotiateBody(dialects ...uint16) []byte {
	b := make([]byte, 36+2*len(dialects))
	le.PutUint16(b[0:], 36)
	le.PutUint16(b[2:], uint16(len(dialects)))
	le.PutUint16(b[4:], 1) // SecurityMode
	le.PutUint32(b[8:], 7) // Capabilities
	copy(b[12:28], "client-guid-0123")
	for i, d := range dialects {
		le.PutUint16(b[36+2*i:], d)
	}
	return b
}

func sessionSetupBody(blob []byte) []byte {
	b := make([]byte, 24, 24+len(blob))
	le.PutUint16(b[0:], 25)
	le.PutUint16(b[12:], smb2HeaderSize+24)
	le.PutUint16(b[14:], uint16(len(blob)))
	return append(b, blob...)
}

func ntlmMessage(msgType uint32) []byte {
	b := append([]byte("NTLMSSP\x00"), make([]byte, 24)...)
	le.PutUint32(b[8:], msgType)
	le.PutUint32(b[12:], 0x80000010) // a few client flags
	return b
}

func treeConnectBody(unc string) []byte {
	path := encodeUTF16LE(unc)
	b := make([]byte, 8, 8+len(path))
	le.PutUint16(b[0:], 9)
	le.PutUint16(b[4:], smb2HeaderSize+8)
	le.PutUint16(b[6:], uint16(len(path)))
	return append(b, path...)
}

func createBody(name string, access, disposition, options uint32) []byte {
	path := encodeUTF16LE(name)
	b := make([]byte, 56, 56+len(path))
	le.PutUint16(b[0:], 57)
	le.PutUint32(b[24:], access)
	le.PutUint32(b[36:], disposition)
	le.PutUint32(b[40:], options)
	le.PutUint16(b[44:], smb2HeaderSize+56)
	le.PutUint16(b[46:], uint16(len(path)))
	return append(b, path...)
}

func closeBody(id []byte) []byte {
	b := make([]byte, 24)
	le.PutUint16(b[0:], 24)
	le.PutUint16(b[2:], closeFlagPostQuery)
	copy(b[8:], id)
	return b
}

func readBody(id []byte, offset uint64, length, minimum uint32) []byte {
	b := make([]byte, 49)
	le.PutUint16(b[0:], 49)
	le.PutUint32(b[4:], length)
	le.PutUint64(b[8:], offset)
	copy(b[16:], id)
	le.PutUint32(b[32:], minimum)
	return b
}

func queryInfoBody(id []byte, infoType, class byte, maxOutput uint32) []byte {
	b := make([]byte, 40)
	le.PutUint16(b[0:], 41)
	b[2] = infoType
	b[3] = class
	le.PutUint32(b[4:], maxOutput)
	copy(b[24:], id)
	return b
}

func queryDirBody(id []byte, class, flags byte, pattern string, maxOutput uint32) []byte {
	name := encodeUTF16LE(pattern)
	b := make([]byte, 32, 32+len(name))
	le.PutUint16(b[0:], 33)
	b[2] = class
	b[3] = flags
	copy(b[8:], id)
	le.PutUint16(b[24:], smb2HeaderSize+32)
	le.PutUint16(b[26:], uint16(len(name)))
	le.PutUint32(b[28:], maxOutput)
	return append(b, name...)
}

// connect performs NEGOTIATE, the guest logon and TREE_CONNECT.
func (c *testClient) connect(dialects ...uint16) {
	c.t.Helper()
	if r := c.call(smb2Negotiate, negotiateBody(dialects...)); r.status != statusOK {
		c.t.Fatalf("NEGOTIATE status %#x", r.status)
	}
	r := c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageNegotiate)))
	if r.status != statusMoreProcessingRequired {
		c.t.Fatalf("SESSION_SETUP 1 status %#x", r.status)
	}
	c.sess = r.sessionID
	r = c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageAuthenticate)))
	if r.status != statusOK {
		c.t.Fatalf("SESSION_SETUP 2 status %#x", r.status)
	}
	r = c.call(smb2TreeConnect, treeConnectBody(`\\host\share`))
	if r.status != statusOK {
		c.t.Fatalf("TREE_CONNECT status %#x", r.status)
	}
	c.tree = r.treeID
}

// open returns the FileId of a successful read-only open.
func (c *testClient) open(name string) []byte {
	c.t.Helper()
	r := c.call(smb2Create, createBody(name, 0x00120089, fileOpen, 0))
	if r.status != statusOK {
		c.t.Fatalf("CREATE %q status %#x", name, r.status)
	}
	return r.body[64:80]
}

// --- Protocol detection ---

func TestIdentifyProtocol(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		want    protocol
		wantErr string
	}{
		{"smb1", []byte("\xFFSMB\x72"), protoSMB1, ""},
		{"smb2", []byte("\xFESMB\x40"), protoSMB2, ""},
		{"encrypted", []byte("\xFDSMB\x00"), 0, "fd 53 4d 42"},
		{"garbage", []byte{1, 2, 3, 4, 5}, 0, "01 02 03 04"},
		{"short", []byte{0xFE}, 0, "fe (1 byte frame)"},
		{"empty", nil, 0, "(0 byte frame)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifyProtocol(tt.frame)
			if got != tt.want {
				t.Errorf("protocol = %v, want %v", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrUnknownProtocol) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want ErrUnknownProtocol containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestUnknownProtocolDropsConnection(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.sendFrame([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0})
	if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
		t.Fatalf("read after unknown frame: %v, want EOF", err)
	}
}

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

// bmcNegotiateFrame is the SMB2 message of the BMC's NEGOTIATE. It is rebuilt
// from the fields decoded in the tcpdump capture (102 bytes, Command NEGOTIATE,
// DialectCount 1, dialect 0x0302, SecurityMode 0x0001, Capabilities 0x00000007);
// the capture's ClientGuid and MessageId values were not preserved.
func bmcNegotiateFrame() []byte {
	body := negotiateBody(0x0302)
	return encodeRequest(smb2Msg{command: smb2Negotiate, credits: 1, body: body})
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

// smb1Negotiate builds an SMB1 NEGOTIATE frame offering dialects.
func smb1Negotiate(dialects ...string) []byte {
	var data []byte
	for _, d := range dialects {
		data = append(data, 0x02)
		data = append(data, d...)
		data = append(data, 0)
	}
	return buildSMB1Request(smbComNegotiate, nil, data)
}

func buildSMB1Request(command byte, words, data []byte) []byte {
	return buildSMBResponse(&smbPacket{
		header: smbHeader{command: command, flags2: smbFlags2Unicode | smbFlags2NTStatus, mid: 7},
		words:  words,
		data:   data,
	})
}

func TestMultiProtocolNegotiate(t *testing.T) {
	tests := []struct {
		name     string
		dialects []string
		wantSMB2 uint16 // 0 means the response must be SMB1
		wantIdx  uint16 // for SMB1
	}{
		{"nt lm only", []string{"NT LM 0.12"}, 0, 0},
		{"nt lm wins over smb2", []string{"PC NETWORK PROGRAM 1.0", "NT LM 0.12", "SMB 2.002", "SMB 2.???"}, 0, 1},
		{"wildcard", []string{"SMB 2.002", "SMB 2.???"}, smb2DialectWildcard, 0},
		{"smb 2.002", []string{"SMB 2.002"}, smb2Dialect202, 0},
		{"nothing known", []string{"LANMAN1.0"}, 0, 0xFFFF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := dialPipe(t, newTestServer(t, nil))
			c.sendFrame(smb1Negotiate(tt.dialects...))
			frame := c.recvFrame()
			if tt.wantSMB2 == 0 {
				pkt, err := parseSMBPacket(frame)
				if err != nil {
					t.Fatal(err)
				}
				if got := binary.LittleEndian.Uint16(pkt.words); got != tt.wantIdx {
					t.Errorf("dialect index %d, want %d", got, tt.wantIdx)
				}
				return
			}
			r := parseResponses(t, frame)[0]
			if r.messageID != 0 || r.command != smb2Negotiate || r.status != statusOK {
				t.Fatalf("response %+v", r)
			}
			if d := le.Uint16(r.body[4:]); d != tt.wantSMB2 {
				t.Errorf("dialect %#x, want %#x", d, tt.wantSMB2)
			}
		})
	}
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

func TestProtocolSwitchDropsConnection(t *testing.T) {
	t.Run("smb1 after smb2", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.call(smb2Negotiate, negotiateBody(0x0210))
		c.sendFrame(smb1Negotiate("NT LM 0.12"))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
	t.Run("smb2 after smb1", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.sendFrame(smb1Negotiate("NT LM 0.12"))
		c.recvFrame()
		c.sendFrame(encodeRequest(smb2Msg{command: smb2Negotiate, body: negotiateBody(0x0210)}))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
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
		want    uint32
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

func (c *testClient) connect2Session() {
	c.t.Helper()
	r := c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageNegotiate)))
	c.sess = r.sessionID
	if r := c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageAuthenticate))); r.status != statusOK {
		c.t.Fatalf("status %#x", r.status)
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
		want        uint32
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
		want     uint32
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

func alignCompound(msgs ...[]byte) []byte {
	var out []byte
	for i, m := range msgs {
		if i < len(msgs)-1 {
			for len(m)%8 != 0 {
				m = append(m, 0)
			}
			le.PutUint32(m[20:], uint32(len(m)))
		}
		out = append(out, m...)
	}
	return out
}

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
		want uint32
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
		want uint32
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

func ioctlBody(code uint32, input []byte, maxOutput uint32) []byte {
	b := make([]byte, 56, 56+len(input))
	le.PutUint16(b[0:], 57)
	le.PutUint32(b[4:], code)
	copy(b[8:24], bytes.Repeat([]byte{0xFF}, 16))
	le.PutUint32(b[24:], smb2HeaderSize+56)
	le.PutUint32(b[28:], uint32(len(input)))
	le.PutUint32(b[44:], maxOutput)
	le.PutUint32(b[48:], 1) // SMB2_0_IOCTL_IS_FSCTL
	return append(b, input...)
}

func validateNegotiateInput(caps uint32, securityMode uint16, dialects ...uint16) []byte {
	b := make([]byte, 24+2*len(dialects))
	le.PutUint32(b[0:], caps)
	copy(b[4:20], "client-guid-0123")
	le.PutUint16(b[20:], securityMode)
	le.PutUint16(b[22:], uint16(len(dialects)))
	for i, d := range dialects {
		le.PutUint16(b[24+2*i:], d)
	}
	return b
}

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
		want    uint32
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

// TestE2ESMB1 is the regression test for the unchanged SMB1 path: the sequence a
// BMC runs, checked at byte level.
func TestE2ESMB1(t *testing.T) {
	content := testContent(100000)
	c := dialPipe(t, newTestServer(t, content))

	roundTrip := func(command byte, words, data []byte) *smbPacket {
		t.Helper()
		c.sendFrame(buildSMB1Request(command, words, data))
		pkt, err := parseSMBPacket(c.recvFrame())
		if err != nil {
			t.Fatal(err)
		}
		if pkt.header.command != command || pkt.header.mid != 7 || pkt.header.flags&smbFlagReply == 0 {
			t.Fatalf("bad reply header: %+v", pkt.header)
		}
		if pkt.header.status != statusOK {
			t.Fatalf("command %#x: status %#x", command, pkt.header.status)
		}
		return pkt
	}

	c.sendFrame(smb1Negotiate("NT LM 0.12"))
	neg, err := parseSMBPacket(c.recvFrame())
	if err != nil {
		t.Fatal(err)
	}
	if len(neg.words) != 34 || binary.LittleEndian.Uint16(neg.words) != 0 {
		t.Fatalf("negotiate words: % x", neg.words)
	}

	setup := roundTrip(smbComSessionSetupAndX, make([]byte, 26), nil)
	if action := binary.LittleEndian.Uint16(setup.words[4:]); action != 1 {
		t.Errorf("action %d, want guest", action)
	}
	tree := roundTrip(smbComTreeConnectAndX, make([]byte, 8), nil)
	if !bytes.HasPrefix(tree.data, []byte("A:\x00")) {
		t.Errorf("tree data %q", tree.data)
	}

	name := append([]byte{0}, encodeUTF16LE(`\`+testFileName)...)
	createWords := make([]byte, 48)
	binary.LittleEndian.PutUint16(createWords[5:], uint16(len(name)-1))
	create := roundTrip(smbComNtCreateAndX, createWords, name)
	if size := binary.LittleEndian.Uint64(create.words[55:]); size != uint64(len(content)) {
		t.Errorf("size %d", size)
	}
	fid := binary.LittleEndian.Uint16(create.words[5:])

	var got []byte
	for len(got) < len(content) {
		words := make([]byte, 24)
		words[0] = 0xFF
		binary.LittleEndian.PutUint16(words[4:], fid)
		binary.LittleEndian.PutUint32(words[6:], uint32(len(got)))
		binary.LittleEndian.PutUint16(words[10:], 60000)
		read := roundTrip(smbComReadAndX, words, nil)
		n := int(binary.LittleEndian.Uint16(read.words[10:]))
		off := int(binary.LittleEndian.Uint16(read.words[12:]))
		if off != 60 || n == 0 {
			t.Fatalf("read offset %d length %d", off, n)
		}
		got = append(got, read.data[1:1+n]...)
	}
	if !bytes.Equal(got, content) {
		t.Error("downloaded content differs")
	}

	roundTrip(smbComClose, make([]byte, 6), nil)
	roundTrip(smbComTreeDisconnect, nil, nil)
	roundTrip(smbComLogoffAndX, make([]byte, 4), nil)
}

func TestSessionRequestFrame(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	if err := writeFrame(c.conn, frameTypeSessionRequest, []byte("names")); err != nil {
		t.Fatal(err)
	}
	if _, msgType, err := readFrame(c.conn); err != nil || msgType != frameTypePositiveSession {
		t.Errorf("type %#x, err %v", msgType, err)
	}
}

// --- Lifecycle ---

func TestServeShutdown(t *testing.T) {
	srv := newTestServer(t, testContent(10))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, frameTypeSessionMessage, encodeRequest(smb2Msg{command: smb2Negotiate, body: negotiateBody(0x0302)})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFrame(conn); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, _, err := readFrame(conn); err == nil {
		t.Error("connection still open after shutdown")
	}
}

func TestServeListenerClosedExternally(t *testing.T) {
	srv := newTestServer(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(context.Background(), ln) }()
	ln.Close()
	select {
	case err := <-serveErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve returned %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve kept running on a closed listener")
	}
}

func TestOpenShareRejectsDirectory(t *testing.T) {
	if _, err := OpenShare(t.TempDir()); err == nil {
		t.Error("expected an error for a directory")
	}
	if _, err := OpenShare(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

// --- Fuzzing ---

func FuzzParseSMB1Packet(f *testing.F) {
	f.Add(smb1Negotiate("NT LM 0.12"))
	f.Add(buildSMB1Request(smbComReadAndX, make([]byte, 24), nil))
	f.Add([]byte{0xFF, 'S', 'M', 'B'})
	f.Fuzz(func(t *testing.T, data []byte) {
		if pkt, err := parseSMBPacket(data); err == nil {
			buildSMBResponse(pkt)
		}
		smb1Dialects(data)
	})
}

// FuzzSMB1Dispatch feeds arbitrary requests to all SMB1 handlers.
func FuzzSMB1Dispatch(f *testing.F) {
	for _, command := range []byte{smbComNegotiate, smbComSessionSetupAndX, smbComTreeConnectAndX,
		smbComNtCreateAndX, smbComReadAndX, smbComClose, smbComTransaction2, smbComEcho} {
		f.Add(buildSMB1Request(command, make([]byte, 60), make([]byte, 40)))
	}
	srv := newTestServer(f, testContent(1000))
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := parseSMBPacket(data)
		if err != nil {
			return
		}
		if err := newSMB1Session(srv).serve(io.Discard, pkt); err != nil {
			t.Fatal(err)
		}
	})
}

func FuzzParseSMB2Message(f *testing.F) {
	f.Add(bmcNegotiateFrame())
	f.Add(alignCompound(encodeRequest(smb2Msg{command: smb2Echo}), encodeRequest(smb2Msg{command: smb2Echo})))
	f.Fuzz(func(t *testing.T, data []byte) {
		for rest := data; len(rest) > 0; {
			req, next, err := parseSMB2Message(rest)
			if err != nil {
				return
			}
			if len(next) >= len(rest) {
				t.Fatalf("no progress: %d -> %d bytes", len(rest), len(next))
			}
			rest = next
			req.payload(smb2HeaderSize, 1)
			req.payload(^uint32(0), ^uint32(0))
		}
	})
}

// FuzzSMB2ServeFrame feeds arbitrary frames to an authenticated connection, so
// the fuzzer reaches every command handler.
func FuzzSMB2ServeFrame(f *testing.F) {
	id := make([]byte, 16)
	le.PutUint64(id, 1)
	le.PutUint64(id[8:], 1)
	msg := func(command uint16, body []byte) []byte {
		return encodeRequest(smb2Msg{command: command, sessionID: 1, treeID: 1, body: body})
	}
	f.Add(msg(smb2Create, createBody(testFileName, 0x80, fileOpen, 0)))
	f.Add(msg(smb2Read, readBody(id, 0, 100, 0)))
	f.Add(msg(smb2Close, closeBody(id)))
	f.Add(msg(smb2QueryInfo, queryInfoBody(id, infoTypeFile, fileAllInformation, 4096)))
	f.Add(msg(smb2QueryInfo, queryInfoBody(id, infoTypeFilesystem, fileFsVolumeInformation, 4096)))
	f.Add(msg(smb2QueryDirectory, queryDirBody(id, fileIDBothDirInformation, 0, "*", 4096)))
	f.Add(msg(smb2Ioctl, ioctlBody(fsctlValidateNegotiateInfo, validateNegotiateInput(7, 1, 0x0302), 24)))
	f.Add(msg(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageNegotiate))))
	f.Add(msg(smb2TreeConnect, treeConnectBody(`\\h\s`)))
	f.Add(alignCompound(msg(smb2Create, createBody(testFileName, 0x80, fileOpen, 0)), msg(smb2Close, closeBody(id))))

	srv := newTestServer(f, testContent(1000))
	f.Fuzz(func(t *testing.T, frame []byte) {
		c := newSMB2Conn(srv, "fuzz")
		c.dialect = smb2Dialect302
		c.sessions[1] = &smb2Session{authenticated: true, trees: map[uint32]*smb2Tree{1: {}}}
		c.handles[1] = &smb2Handle{id: smb2FileID{1, 1}, sessionID: 1, treeID: 1}
		c.lastSession, c.lastTree, c.lastHandle = 1, 1, 1
		_ = c.serveFrame(io.Discard, frame)
	})
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
