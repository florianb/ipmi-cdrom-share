package smbserver

import (
	"fmt"
	"io"
	"log"
	"strings"
	"time"
)

// SMB2 dialects.
const (
	smb2Dialect202      = 0x0202
	smb2Dialect210      = 0x0210
	smb2Dialect300      = 0x0300
	smb2Dialect302      = 0x0302
	smb2DialectWildcard = 0x02FF // only in the response to "SMB 2.???"; the client renegotiates
)

// smb2DialectPreference prefers the simplest dialect a client offers. 3.1.1 is
// missing on purpose: it requires negotiate contexts.
var smb2DialectPreference = []uint16{smb2Dialect210, smb2Dialect202, smb2Dialect302, smb2Dialect300}

const (
	smb2SecurityModeSigningEnabled = 0x0001
	smb2SessionFlagBinding         = 0x01
	smb2SessionFlagIsGuest         = 0x0001

	smb2ShareTypeDisk = 0x01
	smb2ShareTypePipe = 0x02

	// accessReadOnly is FILE_GENERIC_READ | FILE_EXECUTE.
	accessReadOnly = 0x001200A9
)

// smb2ClientInfo holds the NEGOTIATE values that VALIDATE_NEGOTIATE_INFO checks again.
type smb2ClientInfo struct {
	securityMode uint16
	capabilities uint32
	guid         [16]byte
}

// chooseSMB2Dialect returns the most preferred dialect in offered, or 0 for none.
func chooseSMB2Dialect(offered []uint16) uint16 {
	for _, preferred := range smb2DialectPreference {
		for _, d := range offered {
			if d == preferred {
				return d
			}
		}
	}
	return 0
}

// handleNegotiate handles NEGOTIATE ([MS-SMB2] 2.2.3). It reads DialectCount at 2,
// SecurityMode at 4, Capabilities at 8, ClientGuid at 12 and Dialects at 36. Only a
// failed attempt or the wildcard answer may be followed by another NEGOTIATE.
func (c *smb2Conn) handleNegotiate(req *smb2Request, out []byte) ([]byte, ntStatus) {
	if c.dialect != 0 && c.dialect != smb2DialectWildcard {
		c.fatal = fmt.Errorf("%w: repeated NEGOTIATE", errProtocolViolation)
		return out, statusInvalidParameter
	}

	count := int(le.Uint16(req.body[2:]))
	const dialectsOffset = 36
	if count == 0 || len(req.body) < dialectsOffset+2*count {
		return out, statusInvalidParameter
	}
	offered := make([]uint16, count)
	for i := range offered {
		offered[i] = le.Uint16(req.body[dialectsOffset+2*i:])
	}
	dialect := chooseSMB2Dialect(offered)
	if dialect == 0 {
		log.Printf("[%s] SMB2 NEGOTIATE: no supported dialect in %04X", c.remote, offered)
		return out, statusNotSupported
	}

	info := &smb2ClientInfo{
		securityMode: le.Uint16(req.body[4:]),
		capabilities: le.Uint32(req.body[8:]),
	}
	copy(info.guid[:], req.body[12:28])
	c.clientInfo = info
	c.dialect = dialect
	if c.srv.debug != nil {
		log.Printf("[%s] SMB2 client offers %04X, selected %04X (client security mode %#x, capabilities %#x)",
			c.remote, offered, dialect, info.securityMode, info.capabilities)
	}

	return c.appendNegotiateBody(out, dialect), statusOK
}

// appendNegotiateBody appends a NEGOTIATE response ([MS-SMB2] 2.2.4). Signing is
// announced as enabled but not required, which guest sessions never use. No capability is advertised:
// without LARGE_MTU every operation costs one credit and reads stay at 64 KiB.
func (c *smb2Conn) appendNegotiateBody(out []byte, dialect uint16) []byte {
	const bufferOffset = 64
	out, b := growZero(out, bufferOffset+len(spnegoInitToken))
	le.PutUint16(b[0:], 65) // StructureSize
	le.PutUint16(b[2:], smb2SecurityModeSigningEnabled)
	le.PutUint16(b[4:], dialect)
	copy(b[8:24], c.srv.serverGUID[:])
	le.PutUint32(b[28:], maxBufferSize) // MaxTransactSize
	le.PutUint32(b[32:], maxBufferSize) // MaxReadSize
	le.PutUint32(b[36:], maxBufferSize) // MaxWriteSize
	le.PutUint64(b[40:], timeToFiletime(time.Now()))
	le.PutUint16(b[56:], smb2HeaderSize+bufferOffset)
	le.PutUint16(b[58:], uint16(len(spnegoInitToken)))
	copy(b[bufferOffset:], spnegoInitToken)
	return out
}

// serveMultiProtocolNegotiate answers an SMB1 NEGOTIATE with an SMB2 one
// ([MS-SMB2] 3.3.5.3). The response always has MessageId 0.
func (c *smb2Conn) serveMultiProtocolNegotiate(w io.Writer, dialect uint16) error {
	c.dialect = dialect
	out := make([]byte, frameHeaderSize+smb2HeaderSize, 256)
	out = c.appendNegotiateBody(out, dialect)
	putSMB2ResponseHeader(out[frameHeaderSize:], &smb2Header{command: smb2Negotiate}, statusOK)
	putFrameHeader(out, frameTypeSessionMessage, len(out)-frameHeaderSize)
	if _, err := w.Write(out); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// handleSessionSetup handles SESSION_SETUP ([MS-SMB2] 2.2.5), reading Flags at 2,
// SecurityBufferOffset at 12 and SecurityBufferLength at 14. It runs the two-step guest
// logon: NTLMSSP NEGOTIATE gets a CHALLENGE, and any AUTHENTICATE is accepted unchecked
// as guest. Without a session key the session cannot sign, and the guest flag in the
// response (2.2.6) tells the client not to expect it.
func (c *smb2Conn) handleSessionSetup(req *smb2Request, out []byte) ([]byte, ntStatus) {
	if req.body[2]&smb2SessionFlagBinding != 0 {
		return out, statusRequestNotAccepted // no multichannel
	}
	blob, ok := req.payload(uint32(le.Uint16(req.body[12:])), uint32(le.Uint16(req.body[14:])))
	if !ok {
		return out, statusInvalidParameter
	}

	sess := c.sessions[req.sessionID]
	if req.sessionID != 0 && sess == nil {
		return out, statusUserSessionDeleted
	}

	tok, err := parseNTLMToken(blob)
	if err != nil {
		log.Printf("[%s] SMB2 SESSION_SETUP: %v", c.remote, err)
		return out, statusLogonFailure
	}

	var sessionFlags uint16
	var reply []byte
	var status ntStatus
	switch tok.messageType {
	case ntlmMessageNegotiate:
		if sess == nil {
			if len(c.sessions) >= smb2MaxSessions {
				return out, statusInsufficientResources
			}
			c.lastSession++
			sess = &smb2Session{trees: make(map[uint32]*smb2Tree)}
			c.sessions[c.lastSession] = sess
			req.sessionID = c.lastSession
		}
		reply, err = buildNTLMChallenge(tok.flags)
		if err != nil {
			log.Printf("[%s] SMB2 SESSION_SETUP: %v", c.remote, err)
			return out, statusInsufficientResources
		}
		if tok.spnego {
			reply = spnegoChallenge(reply)
		}
		status = statusMoreProcessingRequired

	case ntlmMessageAuthenticate:
		if sess == nil {
			return out, statusLogonFailure
		}
		sess.authenticated = true
		sessionFlags = smb2SessionFlagIsGuest
		if tok.spnego {
			reply = spnegoComplete()
		}
		status = statusOK

	default:
		log.Printf("[%s] SMB2 SESSION_SETUP: unexpected NTLMSSP message type %d", c.remote, tok.messageType)
		return out, statusLogonFailure
	}

	const bufferOffset = 8
	out, b := growZero(out, bufferOffset+len(reply))
	le.PutUint16(b[0:], 9) // StructureSize
	le.PutUint16(b[2:], sessionFlags)
	le.PutUint16(b[4:], smb2HeaderSize+bufferOffset)
	le.PutUint16(b[6:], uint16(len(reply)))
	copy(b[bufferOffset:], reply)
	return out, status
}

// handleLogoff handles LOGOFF ([MS-SMB2] 2.2.7) and closes the handles of the session.
func (c *smb2Conn) handleLogoff(req *smb2Request, out []byte) ([]byte, ntStatus) {
	id := req.sessionID
	delete(c.sessions, id)
	c.dropHandles(func(h *smb2Handle) bool { return h.sessionID == id })
	return appendSmallBody(out), statusOK
}

// handleEcho handles ECHO ([MS-SMB2] 2.2.28).
func (c *smb2Conn) handleEcho(_ *smb2Request, out []byte) ([]byte, ntStatus) {
	return appendSmallBody(out), statusOK
}

// appendSmallBody appends the 4-byte response shared by LOGOFF, ECHO and
// TREE_DISCONNECT ([MS-SMB2] 2.2.8, 2.2.29 and 2.2.12).
func appendSmallBody(out []byte) []byte {
	return append(out, 4, 0, 0, 0)
}

// handleTreeConnect handles TREE_CONNECT ([MS-SMB2] 2.2.9). It reads PathOffset at 4
// and PathLength at 6. The response (2.2.10) holds ShareType at 2 and MaximalAccess at
// 12. Clients connect to IPC$ on their own, so it has to succeed as a pipe share.
func (c *smb2Conn) handleTreeConnect(req *smb2Request, out []byte) ([]byte, ntStatus) {
	path, ok := req.payload(uint32(le.Uint16(req.body[4:])), uint32(le.Uint16(req.body[6:])))
	if !ok {
		return out, statusInvalidParameter
	}
	sess := c.sessions[req.sessionID]
	if len(sess.trees) >= smb2MaxTrees {
		return out, statusInsufficientResources
	}

	// Like SMB1, every share name other than IPC$ reaches the one file.
	unc := decodeUTF16LE(path)
	shareName := unc[strings.LastIndexByte(unc, '\\')+1:]
	isPipe := strings.EqualFold(shareName, "IPC$")

	c.lastTree++
	sess.trees[c.lastTree] = &smb2Tree{isPipe: isPipe}
	req.treeID = c.lastTree

	shareType := byte(smb2ShareTypeDisk)
	if isPipe {
		shareType = smb2ShareTypePipe
	}
	out, b := growZero(out, 16)
	le.PutUint16(b[0:], 16) // StructureSize
	b[2] = shareType
	le.PutUint32(b[12:], accessReadOnly)
	return out, statusOK
}

// handleTreeDisconnect handles TREE_DISCONNECT ([MS-SMB2] 2.2.11) and closes the
// handles of the tree.
func (c *smb2Conn) handleTreeDisconnect(req *smb2Request, out []byte) ([]byte, ntStatus) {
	sessionID, treeID := req.sessionID, req.treeID
	delete(c.sessions[sessionID].trees, treeID)
	c.dropHandles(func(h *smb2Handle) bool { return h.sessionID == sessionID && h.treeID == treeID })
	return appendSmallBody(out), statusOK
}
