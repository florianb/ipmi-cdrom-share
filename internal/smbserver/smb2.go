package smbserver

import (
	"fmt"
	"io"
	"log"
)

const (
	smb2HeaderSize        = 64
	smb2NextCommandOffset = 20
)

// SMB2 command codes.
const (
	smb2Negotiate      = 0x00
	smb2SessionSetup   = 0x01
	smb2Logoff         = 0x02
	smb2TreeConnect    = 0x03
	smb2TreeDisconnect = 0x04
	smb2Create         = 0x05
	smb2Close          = 0x06
	smb2Flush          = 0x07
	smb2Read           = 0x08
	smb2Write          = 0x09
	smb2Lock           = 0x0A
	smb2Ioctl          = 0x0B
	smb2Cancel         = 0x0C
	smb2Echo           = 0x0D
	smb2QueryDirectory = 0x0E
	smb2ChangeNotify   = 0x0F
	smb2QueryInfo      = 0x10
	smb2SetInfo        = 0x11
	smb2OplockBreak    = 0x12
)

// SMB2 header flags.
const (
	smb2FlagServerToRedir = 0x00000001
	smb2FlagRelated       = 0x00000004
)

const (
	// smb2MaxCredits caps the credits granted per response.
	smb2MaxCredits = 128

	// smb2MaxCompoundResponse bounds the output of one compound request. A frame
	// can hold thousands of 64 KiB READs, which must neither exhaust memory nor
	// overflow the 24-bit frame length.
	smb2MaxCompoundResponse = 1 << 19

	smb2MaxSessions = 16
	smb2MaxTrees    = 16
	smb2MaxHandles  = 1024

	// smb2AllOnes in both FileId parts means "the file of the previous request"
	// in a related compound request.
	smb2AllOnes = ^uint64(0)
)

// smb2Header is the 64-byte SMB2 header ([MS-SMB2] 2.2.1). Status and signature are not parsed:
// requests carry a channel sequence in the status field, and guest sessions are
// never signed.
type smb2Header struct {
	creditCharge  uint16
	command       uint16
	creditRequest uint16
	flags         uint32
	nextCommand   uint32
	messageID     uint64
	reserved      uint32
	treeID        uint32
	sessionID     uint64
}

// smb2Request is one message of a possibly compound frame.
type smb2Request struct {
	smb2Header
	msg  []byte // the whole message; request offsets are relative to it
	body []byte // msg without the header
}

// related reports whether the message continues a compound chain and inherits IDs
// from its predecessor ([MS-SMB2] 3.2.4.1.4).
func (r *smb2Request) related() bool { return r.flags&smb2FlagRelated != 0 }

// payload returns a variable-size request field addressed by offset and length.
func (r *smb2Request) payload(offset, length uint32) ([]byte, bool) {
	if length == 0 {
		return nil, true
	}
	if offset < smb2HeaderSize || uint64(offset)+uint64(length) > uint64(len(r.msg)) {
		return nil, false
	}
	return r.msg[offset : offset+length], true
}

// parseSMB2Message splits the first message off data and returns the remainder.
func parseSMB2Message(data []byte) (*smb2Request, []byte, error) {
	if len(data) < smb2HeaderSize {
		return nil, nil, fmt.Errorf("%w: SMB2 message of %d bytes", errProtocolViolation, len(data))
	}
	if [4]byte(data[:4]) != smb2Magic {
		return nil, nil, fmt.Errorf("%w: compound element with identifier % x", errProtocolViolation, data[:4])
	}
	if size := le.Uint16(data[4:]); size != smb2HeaderSize {
		return nil, nil, fmt.Errorf("%w: SMB2 header size %d", errProtocolViolation, size)
	}

	req := &smb2Request{smb2Header: smb2Header{
		creditCharge:  le.Uint16(data[6:]),
		command:       le.Uint16(data[12:]),
		creditRequest: le.Uint16(data[14:]),
		flags:         le.Uint32(data[16:]),
		nextCommand:   le.Uint32(data[20:]),
		messageID:     le.Uint64(data[24:]),
		reserved:      le.Uint32(data[32:]),
		treeID:        le.Uint32(data[36:]),
		sessionID:     le.Uint64(data[40:]),
	}}

	var rest []byte
	end := len(data)
	if next := req.nextCommand; next != 0 {
		if next < smb2HeaderSize || next%8 != 0 || uint64(next) > uint64(len(data)) {
			return nil, nil, fmt.Errorf("%w: NextCommand %d in %d byte frame", errProtocolViolation, next, len(data))
		}
		end = int(next)
		rest = data[end:]
	}
	req.msg = data[:end]
	req.body = data[smb2HeaderSize:end]
	return req, rest, nil
}

// smb2FileID identifies an open handle on the wire.
type smb2FileID struct {
	persistent, volatile uint64
}

// parseSMB2FileID reads a 16-byte FileId field.
func parseSMB2FileID(b []byte) smb2FileID {
	return smb2FileID{persistent: le.Uint64(b), volatile: le.Uint64(b[8:])}
}

// put writes the 16-byte FileId field to b.
func (id smb2FileID) put(b []byte) {
	le.PutUint64(b, id.persistent)
	le.PutUint64(b[8:], id.volatile)
}

// smb2Session is one session of a connection. It exists from the first logon step
// but is only usable once authenticated is set.
type smb2Session struct {
	authenticated bool
	trees         map[uint32]*smb2Tree
}

// smb2Tree is one tree connect. On a pipe tree (IPC$) every open fails.
type smb2Tree struct {
	isPipe bool
}

// smb2Handle is one open of the file or the root directory, valid only within the
// session and tree that created it.
type smb2Handle struct {
	id         smb2FileID
	sessionID  uint64
	treeID     uint32
	isDir      bool
	enumerated bool // QUERY_DIRECTORY has already returned the file
}

// smb2Compound is what related requests inherit from their predecessor.
type smb2Compound struct {
	started      bool
	sessionID    uint64
	treeID       uint32
	fileID       smb2FileID
	hasFile      bool
	createStatus ntStatus // status of a failed CREATE, which fails the related requests after it
}

// smb2Conn is the SMB2 state of one connection.
type smb2Conn struct {
	srv    *Server
	remote string

	dialect    uint16 // 0 before NEGOTIATE
	clientInfo *smb2ClientInfo

	sessions    map[uint64]*smb2Session
	handles     map[uint64]*smb2Handle
	lastSession uint64
	lastTree    uint32
	lastHandle  uint64

	compound  smb2Compound
	fatal     error // set by a handler to drop the connection after the current message
	readBytes int64 // file data read for the current frame
	ioNs      int64 // time spent on it, tracked only in debug mode
}

// newSMB2Conn returns the SMB2 state for a new connection to s from remote.
func newSMB2Conn(s *Server, remote string) *smb2Conn {
	return &smb2Conn{
		srv:      s,
		remote:   remote,
		sessions: make(map[uint64]*smb2Session),
		handles:  make(map[uint64]*smb2Handle),
	}
}

// smb2Scope is the context a command needs before its handler runs.
type smb2Scope int

const (
	scopeConnection smb2Scope = iota
	scopeSession
	scopeTree
)

// smb2Handler appends a response body to out and returns the status. On a failure
// status (see ntStatus.hasBody) the appended bytes are replaced by an error body.
type smb2Handler func(c *smb2Conn, req *smb2Request, out []byte) ([]byte, ntStatus)

// smb2Command describes how a command is checked and handled.
type smb2Command struct {
	name string
	// structureSize is the request's StructureSize field, or 0 for commands that
	// are rejected without looking at the body.
	structureSize uint16
	scope         smb2Scope
	handle        smb2Handler
}

var smb2Commands = map[uint16]smb2Command{
	smb2Negotiate:      {"NEGOTIATE", 36, scopeConnection, (*smb2Conn).handleNegotiate},
	smb2SessionSetup:   {"SESSION_SETUP", 25, scopeConnection, (*smb2Conn).handleSessionSetup},
	smb2Logoff:         {"LOGOFF", 4, scopeSession, (*smb2Conn).handleLogoff},
	smb2TreeConnect:    {"TREE_CONNECT", 9, scopeSession, (*smb2Conn).handleTreeConnect},
	smb2TreeDisconnect: {"TREE_DISCONNECT", 4, scopeTree, (*smb2Conn).handleTreeDisconnect},
	smb2Create:         {"CREATE", 57, scopeTree, (*smb2Conn).handleCreate},
	smb2Close:          {"CLOSE", 24, scopeTree, (*smb2Conn).handleClose},
	smb2Read:           {"READ", 49, scopeTree, (*smb2Conn).handleRead},
	smb2Ioctl:          {"IOCTL", 57, scopeTree, (*smb2Conn).handleIoctl},
	smb2Echo:           {"ECHO", 4, scopeConnection, (*smb2Conn).handleEcho},
	smb2QueryDirectory: {"QUERY_DIRECTORY", 33, scopeTree, (*smb2Conn).handleQueryDirectory},
	smb2QueryInfo:      {"QUERY_INFO", 41, scopeTree, (*smb2Conn).handleQueryInfo},

	smb2Flush:        {"FLUSH", 0, scopeTree, rejectWith(statusAccessDenied)},
	smb2Write:        {"WRITE", 0, scopeTree, rejectWith(statusAccessDenied)},
	smb2SetInfo:      {"SET_INFO", 0, scopeTree, rejectWith(statusAccessDenied)},
	smb2Lock:         {"LOCK", 0, scopeTree, rejectWith(statusNotSupported)},
	smb2ChangeNotify: {"CHANGE_NOTIFY", 0, scopeTree, rejectWith(statusNotSupported)},
	smb2OplockBreak:  {"OPLOCK_BREAK", 0, scopeTree, rejectWith(statusNotSupported)},
}

// rejectWith returns a handler that fails with status without looking at the body.
func rejectWith(status ntStatus) smb2Handler {
	return func(_ *smb2Conn, _ *smb2Request, out []byte) ([]byte, ntStatus) {
		return out, status
	}
}

// growZero extends out by n zero bytes and returns the extended slice and the new part.
func growZero(out []byte, n int) (extended, part []byte) {
	start := len(out)
	out = append(out, make([]byte, n)...)
	return out, out[start:]
}

// serveFrame processes one frame, which may hold several compounded messages, and
// writes all responses as one frame. NextCommand links the responses and each starts
// on an 8-byte boundary. A frame without responses, which only CANCEL requests
// produce, writes nothing.
func (c *smb2Conn) serveFrame(w io.Writer, frame []byte) error {
	debug := c.srv.debug
	start := debug.now()

	bp := readBufPool.Get().(*[]byte)
	defer readBufPool.Put(bp)
	out := (*bp)[:frameHeaderSize]

	c.compound = smb2Compound{}
	c.readBytes, c.ioNs = 0, 0

	prevHeader := -1
	for rest := frame; len(rest) > 0; {
		req, next, err := parseSMB2Message(rest)
		if err != nil {
			return err
		}
		rest = next

		// Nothing is ever pending, so there is nothing to cancel, and CANCEL
		// ([MS-SMB2] 2.2.30) itself has no response.
		if req.command == smb2Cancel {
			continue
		}

		if prevHeader >= 0 {
			for (len(out)-prevHeader)%8 != 0 {
				out = append(out, 0)
			}
			le.PutUint32(out[prevHeader+smb2NextCommandOffset:], uint32(len(out)-prevHeader))
		}
		headerStart := len(out)
		out, _ = growZero(out, smb2HeaderSize)

		var status ntStatus
		out, status = c.dispatch(req, out, len(rest) > 0)
		if c.fatal != nil {
			return c.fatal
		}
		putSMB2ResponseHeader(out[headerStart:], &req.smb2Header, status)
		prevHeader = headerStart
	}
	if prevHeader < 0 {
		return nil
	}

	putFrameHeader(out, frameTypeSessionMessage, len(out)-frameHeaderSize)

	writeStart := debug.now()
	_, err := w.Write(out)
	if c.readBytes > 0 {
		debug.observe(start, writeStart, c.ioNs, c.readBytes)
	}
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// putSMB2ResponseHeader fills the response header for req. Handlers may have
// updated req's session and tree IDs.
func putSMB2ResponseHeader(h []byte, req *smb2Header, status ntStatus) {
	copy(h, smb2Magic[:])
	le.PutUint16(h[4:], smb2HeaderSize)
	le.PutUint16(h[6:], req.creditCharge)
	le.PutUint32(h[8:], uint32(status))
	le.PutUint16(h[12:], req.command)
	le.PutUint16(h[14:], min(max(req.creditRequest, 1), smb2MaxCredits))
	le.PutUint32(h[16:], smb2FlagServerToRedir|req.flags&smb2FlagRelated)
	le.PutUint64(h[24:], req.messageID)
	le.PutUint32(h[32:], req.reserved)
	le.PutUint32(h[36:], req.treeID)
	le.PutUint64(h[40:], req.sessionID)
}

// dispatch appends the body of the response to req and returns the status.
func (c *smb2Conn) dispatch(req *smb2Request, out []byte, more bool) ([]byte, ntStatus) {
	cmd, known := smb2Commands[req.command]
	name := cmd.name
	if !known {
		name = fmt.Sprintf("0x%02X", req.command)
	}

	bodyStart := len(out)
	out, status := c.execute(req, cmd, known, out, more)
	if !status.hasBody() {
		out = append(out[:bodyStart], smb2ErrorBody[:]...)
	}

	c.compound.started = true
	c.compound.sessionID = req.sessionID
	c.compound.treeID = req.treeID

	if c.srv.debug != nil {
		log.Printf("[%s] SMB2 %s mid=%d sess=%d tree=%d status=0x%08X",
			c.remote, name, req.messageID, req.sessionID, req.treeID, status)
	}
	return out, status
}

// smb2ErrorBody is the ERROR response ([MS-SMB2] 2.2.2): StructureSize 9, no error data, and the one
// byte of ErrorData required when ByteCount is 0.
var smb2ErrorBody = [9]byte{9}

// execute runs all checks common to the commands and then the handler: NEGOTIATE
// comes first and alone, related messages inherit the session and tree and the failure
// of an earlier CREATE, the response stays bounded, the body has its StructureSize,
// and the session and tree that the command's scope requires exist.
func (c *smb2Conn) execute(req *smb2Request, cmd smb2Command, known bool, out []byte, more bool) ([]byte, ntStatus) {
	if req.command == smb2Negotiate {
		if c.compound.started || more {
			c.fatal = fmt.Errorf("%w: compounded NEGOTIATE", errProtocolViolation)
			return out, statusInvalidParameter
		}
	} else if c.dialect == 0 || c.dialect == smb2DialectWildcard {
		c.fatal = fmt.Errorf("%w: command 0x%02X before NEGOTIATE", errProtocolViolation, req.command)
		return out, statusInvalidParameter
	}

	if req.related() {
		if !c.compound.started {
			return out, statusInvalidParameter
		}
		req.sessionID = c.compound.sessionID
		req.treeID = c.compound.treeID
		if c.compound.createStatus != statusOK {
			return out, c.compound.createStatus
		}
	}

	if !known {
		return out, statusInvalidParameter
	}
	if len(out) > smb2MaxCompoundResponse {
		return out, statusInsufficientResources
	}
	if size := cmd.structureSize; size != 0 {
		// Odd sizes count one byte of a variable part, which may be absent.
		if len(req.body) < int(size&^1) || le.Uint16(req.body) != size {
			return out, statusInvalidParameter
		}
	}
	if cmd.scope >= scopeSession {
		sess := c.sessions[req.sessionID]
		if sess == nil || !sess.authenticated {
			return out, statusUserSessionDeleted
		}
		if cmd.scope >= scopeTree && sess.trees[req.treeID] == nil {
			return out, statusNetworkNameDeleted
		}
	}
	return cmd.handle(c, req, out)
}

// lookupHandle resolves a FileId field to a handle of the request's session and tree.
func (c *smb2Conn) lookupHandle(req *smb2Request, field []byte) *smb2Handle {
	id := parseSMB2FileID(field)
	if req.related() && id.persistent == smb2AllOnes && id.volatile == smb2AllOnes && c.compound.hasFile {
		id = c.compound.fileID
	}
	h := c.handles[id.volatile]
	if h == nil || h.id != id || h.sessionID != req.sessionID || h.treeID != req.treeID {
		return nil
	}
	return h
}

// dropHandles closes all handles for which match returns true.
func (c *smb2Conn) dropHandles(match func(*smb2Handle) bool) {
	for id, h := range c.handles {
		if match(h) {
			delete(c.handles, id)
		}
	}
}
