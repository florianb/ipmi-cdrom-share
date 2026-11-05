package smbserver

import (
	"bytes"
	"testing"
)

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
				if got := le.Uint16(pkt.words); got != tt.wantIdx {
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
	if len(neg.words) != 34 || le.Uint16(neg.words) != 0 {
		t.Fatalf("negotiate words: % x", neg.words)
	}

	setup := roundTrip(smbComSessionSetupAndX, make([]byte, 26), nil)
	if action := le.Uint16(setup.words[4:]); action != 1 {
		t.Errorf("action %d, want guest", action)
	}
	tree := roundTrip(smbComTreeConnectAndX, make([]byte, 8), nil)
	if !bytes.HasPrefix(tree.data, []byte("A:\x00")) {
		t.Errorf("tree data %q", tree.data)
	}

	name := append([]byte{0}, encodeUTF16LE(`\`+testFileName)...)
	createWords := make([]byte, 48)
	le.PutUint16(createWords[5:], uint16(len(name)-1))
	create := roundTrip(smbComNtCreateAndX, createWords, name)
	if size := le.Uint64(create.words[55:]); size != uint64(len(content)) {
		t.Errorf("size %d", size)
	}
	fid := le.Uint16(create.words[5:])

	var got []byte
	for len(got) < len(content) {
		words := make([]byte, 24)
		words[0] = 0xFF
		le.PutUint16(words[4:], fid)
		le.PutUint32(words[6:], uint32(len(got)))
		le.PutUint16(words[10:], 60000)
		read := roundTrip(smbComReadAndX, words, nil)
		n := int(le.Uint16(read.words[10:]))
		off := int(le.Uint16(read.words[12:]))
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

// TestSMB1ReadHeaderIgnoresStaleBuffer guards the pooled read buffers, which SMB1
// shares with SMB2: nothing an earlier response left behind may reach the client.
// The reference in TestSMB1WireFormat cannot see this, since its buffers only ever
// held SMB1 read responses.
func TestSMB1ReadHeaderIgnoresStaleBuffer(t *testing.T) {
	header := smbHeader{command: smbComReadAndX, flags: smbFlagCaseless, flags2: smbFlags2Unicode, tid: 1, uid: 2, mid: 3}
	const size = frameHeaderSize + smb1ReadDataOffset

	clean := make([]byte, size)
	putSMB1ReadHeader(clean, &header, 100)

	stale := bytes.Repeat([]byte{0xA5}, size)
	putSMB1ReadHeader(stale, &header, 100)

	if !bytes.Equal(clean, stale) {
		t.Errorf("stale data in the response:\nclean % x\nstale % x", clean, stale)
	}
}
