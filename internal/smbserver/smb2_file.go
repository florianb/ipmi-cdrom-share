package smbserver

import (
	"errors"
	"fmt"
	"io"
	"log"
	"slices"
	"strings"
	"time"
)

// CREATE dispositions.
const (
	fileOpen   = 1
	fileCreate = 2
	fileOpenIf = 3
)

// CREATE options.
const (
	createDirectoryFile    = 0x00000001
	createNonDirectoryFile = 0x00000040
	createDeleteOnClose    = 0x00001000
)

// accessWriteMask covers every access right that could modify something:
// WRITE_DATA, APPEND_DATA, WRITE_EA, DELETE_CHILD, WRITE_ATTRIBUTES, DELETE,
// WRITE_DAC, WRITE_OWNER, GENERIC_ALL and GENERIC_WRITE.
const accessWriteMask = 0x00000002 | 0x00000004 | 0x00000010 | 0x00000040 | 0x00000100 |
	0x00010000 | 0x00040000 | 0x00080000 | 0x10000000 | 0x40000000

const (
	fileActionOpened = 1

	allocationUnit     = 4096
	sectorsPerUnit     = 8
	bytesPerSector     = 512
	fsAttributeName    = "FAT"
	maxFileNameLength  = 255
	fileDeviceDisk     = 0x00000007
	deviceReadOnly     = 0x00000002
	fsCasePreserved    = 0x00000002
	fsUnicodeOnDisk    = 0x00000004
	fsReadOnlyVolume   = 0x00080000
	rootIndexNumber    = 1
	fileIndexNumber    = 2
	closeFlagPostQuery = 0x0001
)

// FSCTL codes.
const (
	fsctlDFSGetReferrals       = 0x00060194
	fsctlValidateNegotiateInfo = 0x00140204
)

// smb2Attrs is the metadata reported for a handle.
type smb2Attrs struct {
	isDir      bool
	size       int64
	allocation int64
	attributes uint32
	time       uint64
	index      uint64
}

func (c *smb2Conn) attrs(isDir bool) smb2Attrs {
	a := smb2Attrs{
		isDir:      true,
		attributes: fileAttrDirectory,
		time:       timeToFiletime(c.srv.share.modTime),
		index:      rootIndexNumber,
	}
	if !isDir {
		size := c.srv.share.Size()
		a.isDir = false
		a.size = size
		a.allocation = (size + allocationUnit - 1) / allocationUnit * allocationUnit
		a.attributes = fileAttrReadOnly
		a.index = fileIndexNumber
	}
	return a
}

// putTimes writes the four timestamps of the common file information layout.
func (a smb2Attrs) putTimes(b []byte) {
	for i := 0; i < 4; i++ {
		le.PutUint64(b[8*i:], a.time)
	}
}

// --- CREATE ---

func (c *smb2Conn) handleCreate(req *smb2Request, out []byte) ([]byte, uint32) {
	out, status := c.create(req, out)
	c.compound.createStatus = 0
	if status != statusOK {
		c.compound.createStatus = status
	}
	return out, status
}

func (c *smb2Conn) create(req *smb2Request, out []byte) ([]byte, uint32) {
	b := req.body
	desiredAccess := le.Uint32(b[24:])
	disposition := le.Uint32(b[36:])
	options := le.Uint32(b[40:])
	nameBytes, ok := req.payload(uint32(le.Uint16(b[44:])), uint32(le.Uint16(b[46:])))
	if !ok || len(nameBytes)%2 != 0 {
		return out, statusInvalidParameter
	}
	name := strings.Trim(decodeUTF16LE(nameBytes), `\/`)

	sess := c.sessions[req.sessionID]
	if sess.trees[req.treeID].isPipe {
		return out, statusObjectNameNotFound // no named pipes are served
	}

	isDir := name == ""
	if !isDir && !strings.EqualFold(name, c.srv.share.Name()) {
		if disposition == fileOpen {
			return out, statusObjectNameNotFound
		}
		return out, statusAccessDenied
	}

	switch {
	case desiredAccess&accessWriteMask != 0, options&createDeleteOnClose != 0:
		return out, statusAccessDenied
	case disposition == fileCreate:
		return out, statusObjectNameCollision
	case disposition != fileOpen && disposition != fileOpenIf:
		return out, statusAccessDenied
	case isDir && options&createNonDirectoryFile != 0:
		return out, statusFileIsADirectory
	case !isDir && options&createDirectoryFile != 0:
		return out, statusNotADirectory
	case len(c.handles) >= smb2MaxHandles:
		return out, statusInsufficientResources
	}

	c.lastHandle++
	h := &smb2Handle{
		id:        smb2FileID{persistent: c.lastHandle, volatile: c.lastHandle},
		sessionID: req.sessionID,
		treeID:    req.treeID,
		isDir:     isDir,
	}
	c.handles[h.id.volatile] = h
	c.compound.fileID, c.compound.hasFile = h.id, true

	a := c.attrs(isDir)
	out, r := growZero(out, 88)
	le.PutUint16(r[0:], 89) // StructureSize
	le.PutUint32(r[4:], fileActionOpened)
	a.putTimes(r[8:])
	le.PutUint64(r[40:], uint64(a.allocation))
	le.PutUint64(r[48:], uint64(a.size))
	le.PutUint32(r[56:], a.attributes)
	h.id.put(r[64:])
	return out, statusOK
}

// --- CLOSE ---

func (c *smb2Conn) handleClose(req *smb2Request, out []byte) ([]byte, uint32) {
	h := c.lookupHandle(req, req.body[8:24])
	if h == nil {
		return out, statusFileClosed
	}
	delete(c.handles, h.id.volatile)

	flags := le.Uint16(req.body[2:])
	out, r := growZero(out, 60)
	le.PutUint16(r[0:], 60) // StructureSize
	if flags&closeFlagPostQuery != 0 {
		a := c.attrs(h.isDir)
		le.PutUint16(r[2:], closeFlagPostQuery)
		a.putTimes(r[8:])
		le.PutUint64(r[40:], uint64(a.allocation))
		le.PutUint64(r[48:], uint64(a.size))
		le.PutUint32(r[56:], a.attributes)
	}
	return out, statusOK
}

// --- READ ---

func (c *smb2Conn) handleRead(req *smb2Request, out []byte) ([]byte, uint32) {
	length := le.Uint32(req.body[4:])
	offset := le.Uint64(req.body[8:])
	minimum := le.Uint32(req.body[32:])

	h := c.lookupHandle(req, req.body[16:32])
	if h == nil {
		return out, statusFileClosed
	}
	if h.isDir {
		return out, statusInvalidDeviceRequest
	}
	if length > maxBufferSize {
		return out, statusInvalidParameter
	}
	size := uint64(c.srv.share.Size())
	if offset >= size {
		return out, statusEndOfFile
	}
	want := int(min(uint64(length), size-offset))

	const headerSize = 16
	start := len(out)
	out = slices.Grow(out, headerSize+want)[:start+headerSize+want]
	clear(out[start : start+headerSize])
	data := out[start+headerSize:]

	var ioStart time.Time
	if c.srv.debug != nil {
		ioStart = time.Now()
	}
	n, err := c.srv.share.ReadAt(data, int64(offset))
	if c.srv.debug != nil {
		c.ioNs += time.Since(ioStart).Nanoseconds()
	}
	if err != nil && !errors.Is(err, io.EOF) {
		log.Printf("[%s] ReadAt error at offset %d: %v", c.remote, offset, err)
		return out, statusUnexpectedIOError
	}
	if uint32(n) < minimum || (n == 0 && want > 0) {
		return out, statusEndOfFile
	}
	out = out[:start+headerSize+n]

	r := out[start:]
	le.PutUint16(r[0:], 17) // StructureSize
	r[2] = smb2HeaderSize + headerSize
	le.PutUint32(r[4:], uint32(n))

	if n > 0 {
		c.readBytes += int64(n)
		c.srv.progress.record(int64(offset), n)
	}
	return out, statusOK
}

// --- IOCTL ---

func (c *smb2Conn) handleIoctl(req *smb2Request, out []byte) ([]byte, uint32) {
	code := le.Uint32(req.body[4:])
	switch code {
	case fsctlValidateNegotiateInfo:
		return c.validateNegotiate(req, out)
	case fsctlDFSGetReferrals:
		return out, statusFSDriverRequired
	default:
		log.Printf("[%s] SMB2 IOCTL: unsupported control code 0x%08X", c.remote, code)
		return out, statusNotSupported
	}
}

// validateNegotiate answers VALIDATE_NEGOTIATE_INFO. As specified, a client whose
// values differ from its NEGOTIATE loses the connection.
func (c *smb2Conn) validateNegotiate(req *smb2Request, out []byte) ([]byte, uint32) {
	input, ok := req.payload(le.Uint32(req.body[24:]), le.Uint32(req.body[28:]))
	if !ok || len(input) < 24 {
		return out, statusInvalidParameter
	}
	const responseSize = 24
	if le.Uint32(req.body[44:]) < responseSize {
		return out, statusInvalidParameter
	}
	count := int(le.Uint16(input[22:]))
	if len(input) < 24+2*count {
		return out, statusInvalidParameter
	}
	offered := make([]uint16, count)
	for i := range offered {
		offered[i] = le.Uint16(input[24+2*i:])
	}

	// A connection negotiated through SMB1 has no SMB2 client values to compare.
	if info := c.clientInfo; info != nil {
		if le.Uint32(input[0:]) != info.capabilities ||
			[16]byte(input[4:20]) != info.guid ||
			le.Uint16(input[20:]) != info.securityMode ||
			chooseSMB2Dialect(offered) != c.dialect {
			c.fatal = fmt.Errorf("%w: VALIDATE_NEGOTIATE_INFO does not match NEGOTIATE", errSMB2Protocol)
			return out, statusAccessDenied
		}
	}

	const fixedSize = 48
	out, r := growZero(out, fixedSize+responseSize)
	le.PutUint16(r[0:], 49) // StructureSize
	le.PutUint32(r[4:], fsctlValidateNegotiateInfo)
	copy(r[8:24], req.body[8:24]) // FileId
	le.PutUint32(r[24:], smb2HeaderSize+fixedSize)
	le.PutUint32(r[32:], smb2HeaderSize+fixedSize)
	le.PutUint32(r[36:], responseSize)
	info := r[fixedSize:]
	// Capabilities stay zero, see appendNegotiateBody.
	copy(info[4:20], c.srv.serverGUID[:])
	le.PutUint16(info[20:], smb2SecurityModeSigningEnabled)
	le.PutUint16(info[22:], c.dialect)
	return out, statusOK
}

// --- QUERY_INFO ---

// QUERY_INFO types.
const (
	infoTypeFile       = 1
	infoTypeFilesystem = 2
)

// File information classes.
const (
	fileDirectoryInformation     = 1
	fileFullDirectoryInformation = 2
	fileBothDirectoryInformation = 3
	fileBasicInformation         = 4
	fileStandardInformation      = 5
	fileInternalInformation      = 6
	fileEaInformation            = 7
	fileAccessInformation        = 8
	fileNamesInformation         = 12
	filePositionInformation      = 14
	fileModeInformation          = 16
	fileAlignmentInformation     = 17
	fileAllInformation           = 18
	fileNetworkOpenInformation   = 34
	fileAttributeTagInformation  = 35
	fileIDBothDirInformation     = 37
	fileIDFullDirInformation     = 38
)

// Filesystem information classes.
const (
	fileFsVolumeInformation    = 1
	fileFsSizeInformation      = 3
	fileFsDeviceInformation    = 4
	fileFsAttributeInformation = 5
	fileFsFullSizeInformation  = 7
)

func (c *smb2Conn) handleQueryInfo(req *smb2Request, out []byte) ([]byte, uint32) {
	infoType := req.body[2]
	class := req.body[3]
	maxOutput := le.Uint32(req.body[4:])

	h := c.lookupHandle(req, req.body[24:40])
	if h == nil {
		return out, statusFileClosed
	}

	var data []byte
	var fixed int // size below which a response cannot be truncated
	switch infoType {
	case infoTypeFile:
		data, fixed = c.fileInfo(h, class)
	case infoTypeFilesystem:
		data, fixed = c.fsInfo(class)
	default:
		log.Printf("[%s] SMB2 QUERY_INFO: unsupported info type %d class %d", c.remote, infoType, class)
		return out, statusNotSupported
	}
	if data == nil {
		log.Printf("[%s] SMB2 QUERY_INFO: unsupported type %d class %d", c.remote, infoType, class)
		return out, statusInvalidInfoClass
	}
	if maxOutput < uint32(fixed) {
		return out, statusInfoLengthMismatch
	}

	status := uint32(statusOK)
	if uint64(len(data)) > uint64(maxOutput) {
		data = data[:maxOutput]
		status = statusBufferOverflow
	}
	return appendDataBody(out, data), status
}

// appendDataBody appends the response layout shared by QUERY_INFO and QUERY_DIRECTORY.
func appendDataBody(out, data []byte) []byte {
	const bufferOffset = 8
	out, r := growZero(out, bufferOffset+len(data))
	le.PutUint16(r[0:], 9) // StructureSize
	le.PutUint16(r[2:], smb2HeaderSize+bufferOffset)
	le.PutUint32(r[4:], uint32(len(data)))
	copy(r[bufferOffset:], data)
	return out
}

// fileInfo returns the requested file information and its fixed part's size, or
// nil for an unsupported class.
func (c *smb2Conn) fileInfo(h *smb2Handle, class byte) ([]byte, int) {
	a := c.attrs(h.isDir)

	basic := func(b []byte) {
		a.putTimes(b)
		le.PutUint32(b[32:], a.attributes)
	}
	standard := func(b []byte) {
		le.PutUint64(b[0:], uint64(a.allocation))
		le.PutUint64(b[8:], uint64(a.size))
		le.PutUint32(b[16:], 1) // NumberOfLinks
		if a.isDir {
			b[21] = 1
		}
	}

	switch class {
	case fileBasicInformation:
		b := make([]byte, 40)
		basic(b)
		return b, len(b)
	case fileStandardInformation:
		b := make([]byte, 24)
		standard(b)
		return b, len(b)
	case fileInternalInformation:
		b := make([]byte, 8)
		le.PutUint64(b, a.index)
		return b, len(b)
	case fileEaInformation:
		return make([]byte, 4), 4
	case fileAccessInformation:
		b := make([]byte, 4)
		le.PutUint32(b, accessReadOnly)
		return b, len(b)
	case filePositionInformation:
		return make([]byte, 8), 8
	case fileModeInformation, fileAlignmentInformation:
		return make([]byte, 4), 4
	case fileAllInformation:
		const fixed = 100
		name := `\`
		if !a.isDir {
			name += c.srv.share.Name()
		}
		encoded := encodeUTF16LE(name)
		b := make([]byte, fixed+len(encoded))
		basic(b[0:])
		standard(b[40:])
		le.PutUint64(b[64:], a.index)
		le.PutUint32(b[76:], accessReadOnly)
		le.PutUint32(b[96:], uint32(len(encoded)))
		copy(b[fixed:], encoded)
		return b, fixed
	case fileNetworkOpenInformation:
		b := make([]byte, 56)
		a.putTimes(b)
		le.PutUint64(b[32:], uint64(a.allocation))
		le.PutUint64(b[40:], uint64(a.size))
		le.PutUint32(b[48:], a.attributes)
		return b, len(b)
	case fileAttributeTagInformation:
		b := make([]byte, 8)
		le.PutUint32(b, a.attributes)
		return b, len(b)
	}
	return nil, 0
}

// fsInfo returns the requested filesystem information and its fixed part's size,
// or nil for an unsupported class.
func (c *smb2Conn) fsInfo(class byte) ([]byte, int) {
	// Never report zero units: clients divide by the size.
	units := max(uint64(c.srv.share.Size()+allocationUnit-1)/allocationUnit, 1)

	switch class {
	case fileFsVolumeInformation:
		const fixed = 18
		label := encodeUTF16LE(volumeLabel)
		b := make([]byte, fixed+len(label))
		le.PutUint64(b[0:], timeToFiletime(c.srv.share.modTime))
		le.PutUint32(b[12:], uint32(len(label)))
		copy(b[fixed:], label)
		return b, fixed
	case fileFsSizeInformation:
		b := make([]byte, 24)
		le.PutUint64(b[0:], units)
		le.PutUint32(b[16:], sectorsPerUnit)
		le.PutUint32(b[20:], bytesPerSector)
		return b, len(b)
	case fileFsDeviceInformation:
		b := make([]byte, 8)
		le.PutUint32(b[0:], fileDeviceDisk)
		le.PutUint32(b[4:], deviceReadOnly)
		return b, len(b)
	case fileFsAttributeInformation:
		const fixed = 12
		name := encodeUTF16LE(fsAttributeName)
		b := make([]byte, fixed+len(name))
		le.PutUint32(b[0:], fsCasePreserved|fsUnicodeOnDisk|fsReadOnlyVolume)
		le.PutUint32(b[4:], maxFileNameLength)
		le.PutUint32(b[8:], uint32(len(name)))
		copy(b[fixed:], name)
		return b, fixed
	case fileFsFullSizeInformation:
		b := make([]byte, 32)
		le.PutUint64(b[0:], units)
		le.PutUint32(b[24:], sectorsPerUnit)
		le.PutUint32(b[28:], bytesPerSector)
		return b, len(b)
	}
	return nil, 0
}

const volumeLabel = "IPMI CD Share"

// --- QUERY_DIRECTORY ---

const (
	queryDirRestartScans = 0x01
	queryDirReopen       = 0x10
)

func (c *smb2Conn) handleQueryDirectory(req *smb2Request, out []byte) ([]byte, uint32) {
	class := req.body[2]
	flags := req.body[3]
	maxOutput := le.Uint32(req.body[28:])

	h := c.lookupHandle(req, req.body[8:24])
	if h == nil {
		return out, statusFileClosed
	}
	if !h.isDir {
		return out, statusInvalidParameter
	}
	patternBytes, ok := req.payload(uint32(le.Uint16(req.body[24:])), uint32(le.Uint16(req.body[26:])))
	if !ok {
		return out, statusInvalidParameter
	}

	if flags&(queryDirRestartScans|queryDirReopen) != 0 {
		h.enumerated = false
	}
	if h.enumerated {
		return out, statusNoMoreFiles
	}
	if !matchPattern(decodeUTF16LE(patternBytes), c.srv.share.Name()) {
		return out, statusNoSuchFile
	}

	entry := c.directoryEntry(class)
	if entry == nil {
		log.Printf("[%s] SMB2 QUERY_DIRECTORY: unsupported class %d", c.remote, class)
		return out, statusInvalidInfoClass
	}
	if uint64(len(entry)) > uint64(maxOutput) {
		return out, statusBufferTooSmall
	}
	h.enumerated = true
	return appendDataBody(out, entry), statusOK
}

// directoryEntry builds the file's directory entry, or returns nil for an
// unsupported class. All classes except FileNames start with the same 64 bytes.
func (c *smb2Conn) directoryEntry(class byte) []byte {
	a := c.attrs(false)
	name := encodeUTF16LE(c.srv.share.Name())

	if class == fileNamesInformation {
		const nameOffset = 12
		b := make([]byte, nameOffset+len(name))
		le.PutUint32(b[8:], uint32(len(name)))
		copy(b[nameOffset:], name)
		return b
	}

	var nameOffset, idOffset int
	switch class {
	case fileDirectoryInformation:
		nameOffset = 64
	case fileFullDirectoryInformation:
		nameOffset = 68
	case fileBothDirectoryInformation:
		nameOffset = 94
	case fileIDFullDirInformation:
		nameOffset, idOffset = 80, 72
	case fileIDBothDirInformation:
		nameOffset, idOffset = 104, 96
	default:
		return nil
	}

	b := make([]byte, nameOffset+len(name))
	a.putTimes(b[8:])
	le.PutUint64(b[40:], uint64(a.size))
	le.PutUint64(b[48:], uint64(a.allocation))
	le.PutUint32(b[56:], a.attributes)
	le.PutUint32(b[60:], uint32(len(name)))
	if idOffset != 0 {
		le.PutUint64(b[idOffset:], a.index)
	}
	copy(b[nameOffset:], name)
	return b
}

// matchPattern matches name against a search pattern, ignoring case. It knows
// '*' and '?' plus the DOS forms clients send: '<' behaves like '*', '>' like
// '?', and '"' like '.'. An empty pattern matches everything.
func matchPattern(pattern, name string) bool {
	switch pattern {
	case "", "*", "*.*", "<.*":
		return true
	}
	p := []rune(strings.ToUpper(pattern))
	n := []rune(strings.ToUpper(name))

	pi, ni := 0, 0
	starP, starN := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && (p[pi] == '*' || p[pi] == '<'):
			starP, starN = pi, ni
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == '>' || p[pi] == n[ni] || (p[pi] == '"' && n[ni] == '.')):
			pi++
			ni++
		case starP >= 0:
			starN++
			pi, ni = starP+1, starN
		default:
			return false
		}
	}
	for pi < len(p) && strings.ContainsRune(`*<>"`, p[pi]) {
		pi++
	}
	return pi == len(p)
}
