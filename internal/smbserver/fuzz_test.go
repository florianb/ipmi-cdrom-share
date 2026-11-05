package smbserver

import (
	"io"
	"testing"
)

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
