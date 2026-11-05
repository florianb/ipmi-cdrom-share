package smbserver

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// updateWireGolden rewrites testdata/smb1_wire.golden. The file pins the SMB1
// responses that real BMC firmware has been tested against, so it may only
// change together with a deliberate change of the wire format.
var updateWireGolden = flag.Bool("update-smb1-wire", false, "rewrite the SMB1 wire format reference")

const (
	wireGoldenPath = "testdata/smb1_wire.golden"

	// wireFileSize needs a clamped full-size read and a short read at the end.
	wireFileSize = 200000

	// wireFullDumpLimit is the largest response stored completely. Longer ones
	// keep their first bytes and a hash, so file data does not bloat the reference.
	wireFullDumpLimit = 256
	wirePrefixSize    = 96

	wireUnicode = uint16(0xC807) // UNICODE and NT_STATUS plus bits the server must clear
	wireASCII   = uint16(0x4807) // the same without UNICODE
)

// wireStep is one frame sent to the server. times lists the offsets, relative to
// the SMB header, of timestamps in the response: they hold the current time and
// are checked for plausibility and then blanked.
type wireStep struct {
	name      string
	frameType byte
	payload   []byte
	times     []int
	noReply   bool // the server must stay silent, as it does for unknown frame types
}

// consecutive returns the offsets of n adjacent timestamps.
func consecutive(offset, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = offset + 8*i
	}
	return out
}

// The request helpers below deliberately use nothing from the package under
// test, so that refactoring the server cannot change what the test sends.

func wireRequest(command byte, flags2 uint16, words, data []byte) []byte {
	b := make([]byte, 32+1+len(words)+2+len(data))
	copy(b, "\xFFSMB")
	b[4] = command
	binary.LittleEndian.PutUint32(b[5:], 0xDEADBEEF) // status, ignored in requests
	b[9] = 0x18                                      // CASELESS is echoed, CANONICAL is not
	binary.LittleEndian.PutUint16(b[10:], flags2)
	binary.LittleEndian.PutUint16(b[12:], 0x1122) // PIDHigh
	copy(b[14:22], "SECURITY")
	b[22], b[23] = 0xEE, 0xEE                     // reserved, zero in responses
	binary.LittleEndian.PutUint16(b[24:], 0x3344) // TID
	binary.LittleEndian.PutUint16(b[26:], 0x5566) // PIDLow
	binary.LittleEndian.PutUint16(b[28:], 0x7788) // UID
	binary.LittleEndian.PutUint16(b[30:], 0x99AA) // MID
	b[32] = byte(len(words) / 2)
	copy(b[33:], words)
	binary.LittleEndian.PutUint16(b[33+len(words):], uint16(len(data)))
	copy(b[35+len(words):], data)
	return b
}

func wireUTF16(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

func wireNegotiate(flags2 uint16, dialects ...string) []byte {
	var data []byte
	for _, d := range dialects {
		data = append(append(append(data, 0x02), d...), 0)
	}
	return wireRequest(0x72, flags2, nil, data)
}

func wireCreate(flags2 uint16, nameLen int, data []byte) []byte {
	words := make([]byte, 48)
	binary.LittleEndian.PutUint16(words[5:], uint16(nameLen))
	return wireRequest(0xA2, flags2, words, data)
}

func wireCreateUTF16(name string) []byte {
	encoded := wireUTF16(name)
	return wireCreate(wireUnicode, len(encoded), append([]byte{0}, encoded...))
}

func wireRead(fid uint16, offset uint64, count uint16, wordBytes int) []byte {
	words := make([]byte, wordBytes)
	words[0] = 0xFF
	if wordBytes >= 20 {
		binary.LittleEndian.PutUint16(words[4:], fid)
		binary.LittleEndian.PutUint32(words[6:], uint32(offset))
		binary.LittleEndian.PutUint16(words[10:], count)
	}
	if wordBytes >= 24 {
		binary.LittleEndian.PutUint32(words[20:], uint32(offset>>32))
	}
	return wireRequest(0x2E, wireUnicode, words, nil)
}

// wireTrans2 builds a TRANSACTION2 request whose parameters follow one pad byte.
func wireTrans2(flags2, subcommand uint16, params []byte) []byte {
	const wordBytes = 30
	words := make([]byte, wordBytes)
	binary.LittleEndian.PutUint16(words[18:], uint16(len(params)))
	binary.LittleEndian.PutUint16(words[20:], 32+1+wordBytes+2+1)
	words[26] = 1
	binary.LittleEndian.PutUint16(words[28:], subcommand)
	return wireRequest(0x32, flags2, words, append([]byte{0}, params...))
}

func wireLevel(level uint16) []byte {
	return binary.LittleEndian.AppendUint16(nil, level)
}

func wireQueryPath(flags2, level uint16, path []byte) []byte {
	return wireTrans2(flags2, 0x0005, append(append(wireLevel(level), 0, 0, 0, 0), path...))
}

func wireQueryFile(fid, level uint16) []byte {
	return wireTrans2(wireUnicode, 0x0007, append(wireLevel(fid), wireLevel(level)...))
}

func wireFind(flags2, level uint16, pattern []byte) []byte {
	params := make([]byte, 12)
	binary.LittleEndian.PutUint16(params[6:], level)
	return wireTrans2(flags2, 0x0001, append(params, pattern...))
}

// wireScenarios lists what the test runs, one connection per scenario. They follow
// the BMC sequence and then visit every branch of the SMB1 handlers.
func wireScenarios() []struct {
	name  string
	steps []wireStep
} {
	const (
		fid    = uint16(0x4000)
		dirFID = uint16(0x4001)
	)
	echo := wireRequest(0x2B, wireUnicode, []byte{5, 0}, []byte("ping"))
	nameUTF16 := wireUTF16(`\` + testFileName)

	// Handlers read the unicode state set by NEGOTIATE, so most scenarios start with it.
	negotiate := wireStep{name: "negotiate", payload: wireNegotiate(wireUnicode, "NT LM 0.12"), times: consecutive(56, 1)}

	type scenario = struct {
		name  string
		steps []wireStep
	}
	return []scenario{
		{"bmc", []wireStep{
			negotiate,
			{name: "session setup", payload: wireRequest(0x73, wireUnicode, make([]byte, 26), nil)},
			{name: "tree connect", payload: wireRequest(0x75, wireUnicode, make([]byte, 8), nil)},
			{name: "query fs size", payload: wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))},
			{name: "query fs device", payload: wireTrans2(wireUnicode, 0x0003, wireLevel(0x0104))},
			{name: "query fs attribute", payload: wireTrans2(wireUnicode, 0x0003, wireLevel(0x0105))},
			{name: "find first", payload: wireFind(wireUnicode, 0x0104, wireUTF16(`\*`)), times: consecutive(74, 4)},
			{name: "create", payload: wireCreateUTF16(`\` + testFileName), times: consecutive(44, 4)},
			{name: "query file standard", payload: wireQueryFile(fid, 0x0102)},
			{name: "read", payload: wireRead(fid, 0, 4096, 24)},
			{name: "close", payload: wireRequest(0x04, wireUnicode, make([]byte, 6), nil)},
			{name: "tree disconnect", payload: wireRequest(0x71, wireUnicode, nil, nil)},
			{name: "logoff", payload: wireRequest(0x74, wireUnicode, make([]byte, 4), nil)},
		}},
		{"negotiate", []wireStep{
			{name: "several dialects", payload: wireNegotiate(wireUnicode, "PC NETWORK PROGRAM 1.0", "NT LM 0.12", "SMB 2.002"), times: consecutive(56, 1)},
			{name: "repeated dialect uses the last", payload: wireNegotiate(wireUnicode, "NT LM 0.12", "LANMAN1.0", "NT LM 0.12"), times: consecutive(56, 1)},
			{name: "no known dialect", payload: wireNegotiate(wireASCII, "LANMAN1.0"), times: consecutive(56, 1)},
			{name: "empty", payload: wireNegotiate(wireUnicode), times: consecutive(56, 1)},
			{name: "malformed list", payload: wireRequest(0x72, wireUnicode, nil, []byte("\x02NT LM 0.12\x00\x03LANMAN\x00")), times: consecutive(56, 1)},
			{name: "unterminated dialect", payload: wireRequest(0x72, wireUnicode, nil, []byte("\x02NT LM 0.12")), times: consecutive(56, 1)},
		}},
		{"ascii session", []wireStep{
			{name: "session setup", payload: wireRequest(0x73, wireASCII, make([]byte, 26), nil)},
			{name: "tree connect", payload: wireRequest(0x75, wireASCII, make([]byte, 8), nil)},
			{name: "create", payload: wireCreate(wireASCII, len(testFileName), []byte(testFileName)), times: consecutive(44, 4)},
			{name: "create with slash and nul", payload: wireCreate(wireASCII, len(testFileName)+2, []byte("/"+testFileName+"\x00")), times: consecutive(44, 4)},
			{name: "create length beyond data", payload: wireCreate(wireASCII, 500, []byte(testFileName)), times: consecutive(44, 4)},
			{name: "create unknown", payload: wireCreate(wireASCII, 5, []byte("other"))},
			{name: "query path", payload: wireQueryPath(wireASCII, 0x0101, []byte(`\`+testFileName+"\x00")), times: consecutive(56, 4)},
			{name: "query path missing", payload: wireQueryPath(wireASCII, 0x0101, []byte("other\x00"))},
			{name: "find first", payload: wireFind(wireASCII, 0x0104, []byte(`\*`)), times: consecutive(74, 4)},
			{name: "find first other level", payload: wireFind(wireASCII, 0x0101, []byte(`\*`)), times: consecutive(74, 4)},
		}},
		{"create", []wireStep{
			negotiate,
			{name: "case insensitive", payload: wireCreateUTF16(strings.ToUpper(testFileName)), times: consecutive(44, 4)},
			{name: "root by backslash", payload: wireCreateUTF16(`\`), times: consecutive(44, 4)},
			{name: "root by empty name", payload: wireCreate(wireUnicode, 0, nil), times: consecutive(44, 4)},
			{name: "root by short words", payload: wireRequest(0xA2, wireUnicode, make([]byte, 10), nameUTF16), times: consecutive(44, 4)},
			{name: "unknown", payload: wireCreateUTF16(`\other.iso`)},
			{name: "without pad byte", payload: wireCreate(wireUnicode, len(nameUTF16), nameUTF16), times: consecutive(44, 4)},
			{name: "length beyond data", payload: wireCreate(wireUnicode, 500, append([]byte{0}, nameUTF16...)), times: consecutive(44, 4)},
			{name: "only a pad byte is the root", payload: wireCreate(wireUnicode, 2, []byte{0}), times: consecutive(44, 4)},
		}},
		{"read", []wireStep{
			negotiate,
			{name: "offset", payload: wireRead(fid, 1000, 100, 24)},
			{name: "32-bit form", payload: wireRead(fid, 2000, 100, 20)},
			{name: "clamped to 64 KiB minus headers", payload: wireRead(fid, 0, 0xFFFF, 24)},
			{name: "short at the end", payload: wireRead(fid, wireFileSize-10, 100, 24)},
			{name: "last byte", payload: wireRead(fid, wireFileSize-1, 1, 24)},
			{name: "at the end", payload: wireRead(fid, wireFileSize, 100, 24)},
			{name: "past the end", payload: wireRead(fid, 5<<32, 100, 24)},
			{name: "negative offset", payload: wireRead(fid, 0xFFFFFFFF<<32, 100, 24)},
			{name: "zero count", payload: wireRead(fid, 0, 0, 24)},
			{name: "wrong fid", payload: wireRead(fid+1, 0, 100, 24)},
			{name: "directory fid", payload: wireRead(dirFID, 0, 100, 24)},
			{name: "short words", payload: wireRead(fid, 0, 100, 18)},
			{name: "no words", payload: wireRequest(0x2E, wireUnicode, nil, nil)},
		}},
		{"query fs", []wireStep{
			negotiate,
			{name: "unknown level", payload: wireTrans2(wireUnicode, 0x0003, wireLevel(0x0999))},
			{name: "short parameters", payload: wireTrans2(wireUnicode, 0x0003, []byte{1})},
		}},
		{"query path", []wireStep{
			negotiate,
			{name: "basic", payload: wireQueryPath(wireUnicode, 0x0101, nameUTF16), times: consecutive(56, 4)},
			{name: "standard", payload: wireQueryPath(wireUnicode, 0x0102, nameUTF16)},
			{name: "all", payload: wireQueryPath(wireUnicode, 0x0107, nameUTF16), times: consecutive(56, 4)},
			{name: "case insensitive", payload: wireQueryPath(wireUnicode, 0x0102, wireUTF16(strings.ToUpper(testFileName)))},
			{name: "root basic", payload: wireQueryPath(wireUnicode, 0x0101, wireUTF16(`\`)), times: consecutive(56, 4)},
			{name: "root standard", payload: wireQueryPath(wireUnicode, 0x0102, nil)},
			{name: "root all", payload: wireQueryPath(wireUnicode, 0x0107, nil), times: consecutive(56, 4)},
			{name: "unknown level", payload: wireQueryPath(wireUnicode, 0x0999, nameUTF16)},
			{name: "missing", payload: wireQueryPath(wireUnicode, 0x0101, wireUTF16(`\other.iso`))},
			{name: "short parameters", payload: wireTrans2(wireUnicode, 0x0005, make([]byte, 5))},
		}},
		{"query file", []wireStep{
			negotiate,
			{name: "basic", payload: wireQueryFile(fid, 0x0101), times: consecutive(56, 4)},
			{name: "all", payload: wireQueryFile(fid, 0x0107), times: consecutive(56, 4)},
			{name: "other fid is the directory", payload: wireQueryFile(dirFID, 0x0102)},
			{name: "unknown level", payload: wireQueryFile(fid, 0x0999)},
			{name: "short parameters", payload: wireTrans2(wireUnicode, 0x0007, make([]byte, 3))},
		}},
		{"find first", []wireStep{
			negotiate,
			{name: "other level", payload: wireFind(wireUnicode, 0x0101, wireUTF16(`\*`)), times: consecutive(74, 4)},
			{name: "pattern is ignored", payload: wireFind(wireUnicode, 0x0104, wireUTF16(`\nomatch`)), times: consecutive(74, 4)},
			{name: "short parameters", payload: wireTrans2(wireUnicode, 0x0001, make([]byte, 11))},
		}},
		{"trans2 framing", []wireStep{
			negotiate,
			{name: "unknown subcommand", payload: wireTrans2(wireUnicode, 0x0099, wireLevel(1))},
			{name: "short words", payload: wireRequest(0x32, wireUnicode, make([]byte, 26), nil)},
			{name: "no setup words", payload: func() []byte {
				p := wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))
				p[33+26] = 0
				return p
			}()},
			{name: "setup count beyond words", payload: func() []byte {
				p := wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))
				p[33+26] = 5
				return p
			}()},
			{name: "parameter count beyond data uses the rest", payload: func() []byte {
				p := wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))
				binary.LittleEndian.PutUint16(p[33+18:], 100)
				return p
			}()},
			{name: "parameter offset before data", payload: func() []byte {
				p := wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))
				binary.LittleEndian.PutUint16(p[33+20:], 10)
				return p
			}()},
			{name: "parameter offset past data", payload: func() []byte {
				p := wireTrans2(wireUnicode, 0x0003, wireLevel(0x0103))
				binary.LittleEndian.PutUint16(p[33+20:], 5000)
				return p
			}()},
		}},
		{"other commands", []wireStep{
			{name: "echo before negotiate", payload: echo},
			negotiate,
			{name: "echo", payload: echo},
			{name: "byte count beyond frame", payload: func() []byte {
				p := wireRequest(0x2B, wireUnicode, []byte{5, 0}, []byte("ping"))
				binary.LittleEndian.PutUint16(p[35:], 1000)
				return p
			}()},
			{name: "unknown command", payload: wireRequest(0x99, wireUnicode, nil, nil)},
			{name: "not unicode flags", payload: wireRequest(0x2B, 0x0003, []byte{1, 0}, nil)},
		}},
		{"netbios", []wireStep{
			{name: "session request", frameType: 0x81, payload: []byte("names")},
			{name: "keepalive is ignored", frameType: 0x85, noReply: true},
			{name: "echo", payload: echo},
		}},
		{"frame without words", []wireStep{
			negotiate,
			{name: "too short", payload: []byte("\xFFSMB\x2B")},
		}},
		{"truncated words", []wireStep{
			negotiate,
			{name: "word count beyond frame", payload: func() []byte {
				p := wireRequest(0x2B, wireUnicode, nil, nil)
				p[32] = 200
				return p
			}()},
		}},
		{"protocol switch", []wireStep{
			negotiate,
			{name: "smb2 frame", payload: append([]byte("\xFESMB"), make([]byte, 60)...)},
		}},
		{"unknown protocol", []wireStep{
			{name: "garbage", payload: []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0}},
		}},
	}
}

// wireRoundTrip sends one frame and returns the raw response including the
// NetBIOS header, or nil if the server closed the connection.
func wireRoundTrip(t *testing.T, conn io.ReadWriter, step wireStep) []byte {
	t.Helper()
	frame := make([]byte, 4+len(step.payload))
	frame[0] = step.frameType
	frame[1] = byte(len(step.payload) >> 16)
	frame[2] = byte(len(step.payload) >> 8)
	frame[3] = byte(len(step.payload))
	copy(frame[4:], step.payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("%s: write: %v", step.name, err)
	}
	if step.noReply {
		return []byte{}
	}

	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		t.Fatalf("%s: read: %v", step.name, err)
	}
	length := int(header[1])<<16 | int(header[2])<<8 | int(header[3])
	response := append(header, make([]byte, length)...)
	if _, err := io.ReadFull(conn, response[4:]); err != nil {
		t.Fatalf("%s: read: %v", step.name, err)
	}
	return response
}

// blankTimes zeroes the timestamps of a response after checking that they are
// the current time, which also proves that the offsets in the scenarios are right.
func blankTimes(t *testing.T, step wireStep, response []byte) {
	t.Helper()
	const unixEpochAsFiletime = 116444736000000000
	for _, off := range step.times {
		field := response[4+off : 4+off+8]
		ns := int64(binary.LittleEndian.Uint64(field)-unixEpochAsFiletime) * 100
		if diff := time.Since(time.Unix(0, ns)); diff < -time.Minute || diff > time.Minute {
			t.Errorf("%s: offset %d is not a current timestamp: % x", step.name, off, field)
		}
		clear(field)
	}
}

// formatWireResponse renders a response as hex lines that diff well.
func formatWireResponse(response []byte) string {
	switch {
	case response == nil:
		return "  connection closed\n"
	case len(response) == 0:
		return "  no response\n"
	}
	dump := response
	summary := ""
	if len(response) > wireFullDumpLimit {
		dump = response[:wirePrefixSize]
		summary = fmt.Sprintf("  ... %d bytes in total, sha256 %x\n", len(response), sha256.Sum256(response))
	}
	var b strings.Builder
	for len(dump) > 0 {
		n := min(len(dump), 32)
		b.WriteString("  " + hex.EncodeToString(dump[:n]) + "\n")
		dump = dump[n:]
	}
	b.WriteString(summary)
	return b.String()
}

// wireTranscript runs all scenarios and renders the responses.
func wireTranscript(t *testing.T, debug bool) string {
	t.Helper()
	var transcript strings.Builder
	for _, sc := range wireScenarios() {
		srv := newTestServer(t, testContent(wireFileSize))
		if debug {
			srv.debug = &debugStats{}
		}
		c := dialPipe(t, srv)
		fmt.Fprintf(&transcript, "== %s\n", sc.name)
		for _, step := range sc.steps {
			response := wireRoundTrip(t, c.conn, step)
			blankTimes(t, step, response)
			fmt.Fprintf(&transcript, "%s\n%s", step.name, formatWireResponse(response))
		}
	}
	return transcript.String()
}

// TestSMB1WireFormat compares every SMB1 response byte for byte with the reference.
func TestSMB1WireFormat(t *testing.T) {
	got := wireTranscript(t, false)
	if debug := wireTranscript(t, true); debug != got {
		t.Error("debug mode changes the SMB1 responses")
	}

	if *updateWireGolden {
		if err := os.MkdirAll(filepath.Dir(wireGoldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(wireGoldenPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}

	wantBytes, err := os.ReadFile(wireGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(wantBytes); got != want {
		gotLines, wantLines := strings.Split(got, "\n"), strings.Split(want, "\n")
		for i := 0; i < min(len(gotLines), len(wantLines)); i++ {
			if gotLines[i] != wantLines[i] {
				t.Fatalf("SMB1 wire format changed at line %d:\n got %s\nwant %s", i+1, gotLines[i], wantLines[i])
			}
		}
		t.Fatalf("SMB1 wire format changed: %d lines, reference has %d", len(gotLines), len(wantLines))
	}
}
