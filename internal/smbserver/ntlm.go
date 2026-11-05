package smbserver

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// This file implements just enough SPNEGO and NTLMSSP for SMB2 guest logons.
// Credentials are never checked and no session key is derived.

const (
	ntlmMessageNegotiate    = 1
	ntlmMessageChallenge    = 2
	ntlmMessageAuthenticate = 3

	ntlmChallengeHeaderSize = 56
)

// NTLMSSP negotiate flags.
const (
	ntlmFlagUnicode       = 0x00000001
	ntlmFlagRequestTarget = 0x00000004
	ntlmFlagNTLM          = 0x00000200
	ntlmFlagTargetServer  = 0x00020000
	ntlmFlagTargetInfo    = 0x00800000

	// ntlmEchoedFlags are granted exactly when the client asks for them. Clients
	// may refuse a CHALLENGE lacking a flag they require, and the values have no
	// effect here because guest sessions never sign or seal.
	ntlmEchoedFlags = 0x00000010 | // SIGN
		0x00000020 | // SEAL
		0x00008000 | // ALWAYS_SIGN
		0x00080000 | // EXTENDED_SESSIONSECURITY
		0x02000000 | // VERSION
		0x20000000 | // 128
		0x40000000 | // KEY_EXCH
		0x80000000 // 56
)

// AV pair identifiers of the CHALLENGE target info. MsvAvTimestamp is left out on
// purpose: it makes clients send a MIC, and they would then expect a signed
// SPNEGO completion that a guest logon cannot produce.
const (
	ntlmAvEOL            = 0
	ntlmAvNbComputerName = 1
	ntlmAvNbDomainName   = 2
)

const (
	ntlmTargetName = "IPMICDSHARE"
	ntlmDomainName = "WORKGROUP"
)

var (
	ntlmSignature = []byte("NTLMSSP\x00")
	oidSPNEGO     = []byte{0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLMSSP    = []byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}

	errNoNTLMToken = errors.New("no NTLMSSP token in security buffer")
)

// ntlmToken is the NTLMSSP message found in a SESSION_SETUP security buffer.
type ntlmToken struct {
	messageType uint32
	flags       uint32 // only set on NEGOTIATE messages
	spnego      bool   // the token arrived wrapped, so the reply must be wrapped too
}

// parseNTLMToken locates the NTLMSSP message in blob, either raw or inside
// SPNEGO. It searches for the signature instead of decoding the DER wrapper:
// nothing in the wrapper matters for a guest logon, and firmware clients are
// known for loose encodings.
func parseNTLMToken(blob []byte) (ntlmToken, error) {
	idx := bytes.Index(blob, ntlmSignature)
	if idx < 0 {
		return ntlmToken{}, errNoNTLMToken
	}
	msg := blob[idx:]
	if len(msg) < 12 {
		return ntlmToken{}, fmt.Errorf("truncated NTLMSSP message: %d bytes", len(msg))
	}
	tok := ntlmToken{
		messageType: binary.LittleEndian.Uint32(msg[8:12]),
		spnego:      idx != 0,
	}
	if tok.messageType == ntlmMessageNegotiate && len(msg) >= 16 {
		tok.flags = binary.LittleEndian.Uint32(msg[12:16])
	}
	return tok, nil
}

// buildNTLMChallenge returns a CHALLENGE message answering clientFlags.
func buildNTLMChallenge(clientFlags uint32) ([]byte, error) {
	target := encodeUTF16LE(ntlmTargetName)

	var info []byte
	info = appendAvPair(info, ntlmAvNbDomainName, encodeUTF16LE(ntlmDomainName))
	info = appendAvPair(info, ntlmAvNbComputerName, target)
	info = appendAvPair(info, ntlmAvEOL, nil)

	flags := clientFlags&ntlmEchoedFlags |
		ntlmFlagUnicode | ntlmFlagRequestTarget | ntlmFlagNTLM |
		ntlmFlagTargetServer | ntlmFlagTargetInfo

	msg := make([]byte, ntlmChallengeHeaderSize, ntlmChallengeHeaderSize+len(target)+len(info))
	copy(msg, ntlmSignature)
	binary.LittleEndian.PutUint32(msg[8:], ntlmMessageChallenge)
	putNTLMField(msg[12:], len(target), ntlmChallengeHeaderSize)
	binary.LittleEndian.PutUint32(msg[20:], flags)
	if _, err := rand.Read(msg[24:32]); err != nil {
		return nil, fmt.Errorf("generate NTLM challenge: %w", err)
	}
	putNTLMField(msg[40:], len(info), ntlmChallengeHeaderSize+len(target))
	msg[48] = 6 // Version: 6.1, purely informational
	msg[49] = 1
	msg[55] = 15 // NTLMSSP_REVISION_W2K3

	msg = append(msg, target...)
	msg = append(msg, info...)
	return msg, nil
}

func appendAvPair(b []byte, id uint16, value []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, id)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(value)))
	return append(b, value...)
}

// putNTLMField writes an NTLMSSP payload descriptor (length, max length, offset).
func putNTLMField(b []byte, length, offset int) {
	binary.LittleEndian.PutUint16(b[0:], uint16(length))
	binary.LittleEndian.PutUint16(b[2:], uint16(length))
	binary.LittleEndian.PutUint32(b[4:], uint32(offset))
}

// --- SPNEGO (DER) ---

// derTLV encodes a tag-length-value element. All values here are far below 64 KiB.
func derTLV(tag byte, parts ...[]byte) []byte {
	value := bytes.Join(parts, nil)
	out := []byte{tag}
	switch n := len(value); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, value...)
}

const (
	derOID         = 0x06
	derOctetString = 0x04
	derEnumerated  = 0x0A
	derSequence    = 0x30
	derApplication = 0x60
	derContext0    = 0xA0
	derContext1    = 0xA1
	derContext2    = 0xA2

	spnegoAcceptCompleted  = 0
	spnegoAcceptIncomplete = 1
)

// spnegoInitToken is the NegTokenInit of the NEGOTIATE response. It offers NTLMSSP only.
var spnegoInitToken = derTLV(derApplication,
	derTLV(derOID, oidSPNEGO),
	derTLV(derContext0,
		derTLV(derSequence,
			derTLV(derContext0,
				derTLV(derSequence, derTLV(derOID, oidNTLMSSP))))))

// spnegoChallenge wraps an NTLMSSP CHALLENGE in a NegTokenResp.
func spnegoChallenge(challenge []byte) []byte {
	return derTLV(derContext1,
		derTLV(derSequence,
			derTLV(derContext0, derTLV(derEnumerated, []byte{spnegoAcceptIncomplete})),
			derTLV(derContext1, derTLV(derOID, oidNTLMSSP)),
			derTLV(derContext2, derTLV(derOctetString, challenge))))
}

// spnegoComplete returns the NegTokenResp ending a successful logon.
func spnegoComplete() []byte {
	return derTLV(derContext1,
		derTLV(derSequence,
			derTLV(derContext0, derTLV(derEnumerated, []byte{spnegoAcceptCompleted}))))
}
