package smbserver

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
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
	srv, err := NewServer(share, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

// --- SMB2 test client ---

// smb2Msg is a request to send or a parsed response.
type smb2Msg struct {
	command   uint16
	status    ntStatus
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
			status:    ntStatus(le.Uint32(frame[8:])),
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

func (c *testClient) connect2Session() {
	c.t.Helper()
	r := c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageNegotiate)))
	c.sess = r.sessionID
	if r := c.call(smb2SessionSetup, sessionSetupBody(ntlmMessage(ntlmMessageAuthenticate))); r.status != statusOK {
		c.t.Fatalf("status %#x", r.status)
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
