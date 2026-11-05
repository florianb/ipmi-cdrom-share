package smbserver

import (
	"log"
	"strings"
	"time"
)

// Filesystem values only SMB1 reports ([MS-FSCC] 2.5.10 and 2.5.1). SMB2 uses other
// ones, see smb2_file.go. Real firmware has been tested against these, so they stay
// although neither describes the share well: FILE_DEVICE_IS_MOUNTED does not say
// read-only, and names are in fact compared without regard to case.
const (
	fileDeviceIsMounted   = 0x00000020
	fsCaseSensitiveSearch = 0x00000001
)

// --- TRANSACTION2 (0x32) ---

// handleTrans2 unpacks SMB_COM_TRANSACTION2 ([MS-CIFS] 2.2.4.46) and runs its
// subcommand. It reads ParameterCount at 18, ParameterOffset at 20, SetupCount at 26
// and the subcommand in Setup at 28. Follow-up messages of a split request are not
// implemented: the parameters of the supported subcommands fit into one. If
// ParameterCount exceeds the data, the rest of the data serves as parameters.
func (sess *smb1Session) handleTrans2(req *smbPacket) (*smbPacket, ntStatus) {
	if len(req.words) < 28 {
		return nil, statusNotImplemented
	}

	setupCount := int(req.words[26])
	if setupCount < 1 || len(req.words) < 28+setupCount*2 {
		return nil, statusNotImplemented
	}
	subcommand := le.Uint16(req.words[28:])

	paramCount := int(le.Uint16(req.words[18:]))
	paramOffset := int(le.Uint16(req.words[20:]))

	// Convert paramOffset (from SMB header start) to data section offset.
	headerLen := smb1HeaderSize + 1 + len(req.words) + 2
	transParamStart := paramOffset - headerLen
	var transParams []byte
	if transParamStart >= 0 && transParamStart+paramCount <= len(req.data) {
		transParams = req.data[transParamStart : transParamStart+paramCount]
	} else if transParamStart >= 0 && transParamStart < len(req.data) {
		transParams = req.data[transParamStart:]
	}

	switch subcommand {
	case trans2FindFirst2:
		return sess.handleFindFirst2(req, transParams)
	case trans2QueryFSInfo:
		return sess.handleQueryFSInfo(req, transParams)
	case trans2QueryPathInfo:
		return sess.handleQueryPathInfo(req, transParams)
	case trans2QueryFileInfo:
		return sess.handleQueryFileInfo(req, transParams)
	default:
		log.Printf("Unhandled TRANS2 subcommand: 0x%04X", subcommand)
		return nil, statusNotImplemented
	}
}

// handleQueryFSInfo answers TRANS2_QUERY_FS_INFORMATION ([MS-CIFS] 2.2.6.4). The
// parameters hold InformationLevel at 0. The total size rounds down, unlike in SMB2,
// so a file below one allocation unit reports zero units.
func (sess *smb1Session) handleQueryFSInfo(req *smbPacket, transParams []byte) (*smbPacket, ntStatus) {
	if len(transParams) < 2 {
		return nil, statusNotImplemented
	}
	infoLevel := le.Uint16(transParams)
	log.Printf("QUERY_FS_INFO level=0x%04X", infoLevel)

	var infoData []byte

	switch infoLevel {
	case smbQueryFSSizeInfo:
		// TotalUnits(8) + FreeUnits(8) + SectorsPerUnit(4) + BytesPerSector(4)
		infoData = make([]byte, 24)
		le.PutUint64(infoData[0:], uint64(sess.srv.share.Size())/allocationUnit)
		// FreeUnits = 0 (read-only)
		le.PutUint32(infoData[16:], sectorsPerUnit)
		le.PutUint32(infoData[20:], bytesPerSector)

	case smbQueryFSDeviceInfo:
		// DeviceType(4) + Characteristics(4)
		infoData = make([]byte, 8)
		le.PutUint32(infoData[0:], fileDeviceDisk)
		le.PutUint32(infoData[4:], fileDeviceIsMounted)

	case smbQueryFSAttributeInfo:
		// Attributes(4) + MaxNameLen(4) + FSNameLen(4) + FSName
		fsName := encodeUTF16LE(fsAttributeName)
		infoData = make([]byte, 12+len(fsName))
		le.PutUint32(infoData[0:], fsCaseSensitiveSearch)
		le.PutUint32(infoData[4:], maxFileNameLength)
		le.PutUint32(infoData[8:], uint32(len(fsName)))
		copy(infoData[12:], fsName)

	default:
		log.Printf("Unhandled FS info level: 0x%04X", infoLevel)
		return nil, statusNotImplemented
	}

	return buildTrans2Response(req, nil, infoData), statusOK
}

// handleQueryPathInfo answers TRANS2_QUERY_PATH_INFORMATION ([MS-CIFS] 2.2.6.6). The
// parameters hold InformationLevel at 0 and FileName at 6. An empty path is the root.
func (sess *smb1Session) handleQueryPathInfo(req *smbPacket, transParams []byte) (*smbPacket, ntStatus) {
	if len(transParams) < 6 {
		return nil, statusNotImplemented
	}

	infoLevel := le.Uint16(transParams)
	path := strings.TrimPrefix(sess.decodeString(transParams[6:]), "\\")
	log.Printf("QUERY_PATH_INFO level=0x%04X path=%q", infoLevel, path)

	share := sess.srv.share
	if path == "" {
		return buildFileInfoResponse(req, infoLevel, true, 0)
	}
	if strings.EqualFold(path, share.Name()) {
		return buildFileInfoResponse(req, infoLevel, false, share.Size())
	}
	return nil, statusObjectNameNotFound
}

// handleQueryFileInfo answers TRANS2_QUERY_FILE_INFORMATION ([MS-CIFS] 2.2.6.8). The
// parameters hold FID at 0 and InformationLevel at 2. Every FID other than the file's
// counts as the root directory.
func (sess *smb1Session) handleQueryFileInfo(req *smbPacket, transParams []byte) (*smbPacket, ntStatus) {
	if len(transParams) < 4 {
		return nil, statusNotImplemented
	}

	fid := le.Uint16(transParams)
	infoLevel := le.Uint16(transParams[2:])
	log.Printf("QUERY_FILE_INFO fid=0x%04X level=0x%04X", fid, infoLevel)

	if fid == smb1FileFID {
		return buildFileInfoResponse(req, infoLevel, false, sess.srv.share.Size())
	}
	return buildFileInfoResponse(req, infoLevel, true, 0)
}

// buildFileInfoResponse answers a query for the file or the root directory. The
// timestamps are the current time.
func buildFileInfoResponse(req *smbPacket, infoLevel uint16, isDir bool, size int64) (*smbPacket, ntStatus) {
	now := timeToFiletime(time.Now())
	attr := uint32(fileAttrReadOnly)
	if isDir {
		attr = fileAttrDirectory
	}

	var infoData []byte

	switch infoLevel {
	case smbQueryFileBasicInfo:
		infoData = make([]byte, 40)
		putTimes(infoData, now)
		le.PutUint32(infoData[32:], attr)

	case smbQueryFileStandardInfo:
		infoData = make([]byte, 22)
		le.PutUint64(infoData[0:], uint64(size))
		le.PutUint64(infoData[8:], uint64(size))
		le.PutUint32(infoData[16:], 1) // NumberOfLinks
		if isDir {
			infoData[21] = 1
		}

	case smbQueryFileAllInfo:
		infoData = make([]byte, 72)
		putTimes(infoData, now)
		le.PutUint32(infoData[32:], attr)
		// Pad at 36:40
		le.PutUint64(infoData[40:], uint64(size))
		le.PutUint64(infoData[48:], uint64(size))
		le.PutUint32(infoData[56:], 1) // NumberOfLinks
		if isDir {
			infoData[61] = 1
		}
		// EaSize(4) at 64, FileNameLength(4) at 68 = 0

	default:
		return nil, statusNotImplemented
	}

	return buildTrans2Response(req, nil, infoData), statusOK
}

// handleFindFirst2 answers TRANS2_FIND_FIRST2 ([MS-CIFS] 2.2.6.2). The parameters
// hold InformationLevel at 6 and FileName, the search pattern, at 12. The pattern is
// only logged: the response always lists the file. No search state remains, because
// EndOfSearch is always set and no FIND_NEXT2 can follow.
func (sess *smb1Session) handleFindFirst2(req *smbPacket, transParams []byte) (*smbPacket, ntStatus) {
	if len(transParams) < 12 {
		return nil, statusNotImplemented
	}

	infoLevel := le.Uint16(transParams[6:])
	pattern := sess.decodeString(transParams[12:])
	log.Printf("FIND_FIRST2 level=0x%04X pattern=%q", infoLevel, pattern)

	share := sess.srv.share
	nameBytes := sess.encodeString(share.Name())

	// Both layouts share everything up to FileNameLength. FILE_BOTH_DIR_INFO then
	// adds EaSize, ShortNameLength, a reserved byte and ShortName, all zero. Other
	// levels fall back to FILE_DIRECTORY_INFO.
	nameOffset := 64
	if infoLevel == smbFindFileBothDirInfo {
		nameOffset = 94
	}
	entryData := make([]byte, nameOffset+len(nameBytes))
	// NextEntryOffset(4)=0, FileIndex(4)=0
	putTimes(entryData[8:], timeToFiletime(time.Now()))
	le.PutUint64(entryData[40:], uint64(share.Size()))
	le.PutUint64(entryData[48:], uint64(share.Size()))
	le.PutUint32(entryData[56:], fileAttrReadOnly)
	le.PutUint32(entryData[60:], uint32(len(nameBytes)))
	copy(entryData[nameOffset:], nameBytes)

	// FIND_FIRST2 response parameters.
	respParams := make([]byte, 10)
	le.PutUint16(respParams[0:], 0x0001) // SID
	le.PutUint16(respParams[2:], 1)      // SearchCount
	le.PutUint16(respParams[4:], 1)      // EndOfSearch
	return buildTrans2Response(req, respParams, entryData), statusOK
}

// buildTrans2Response wraps parameters and data in a TRANSACTION2 response
// ([MS-CIFS] 2.2.4.46): ParameterCount at 6, ParameterOffset at 8, DataCount at 12
// and DataOffset at 14, with the totals repeated at 0 and 2. Offsets count from the
// start of the SMB header.
func buildTrans2Response(req *smbPacket, transParams, transData []byte) *smbPacket {
	resp := newResponse(req)

	// WordCount = 10 (20 bytes).
	words := make([]byte, 20)
	le.PutUint16(words[0:], uint16(len(transParams)))
	le.PutUint16(words[2:], uint16(len(transData)))
	le.PutUint16(words[6:], uint16(len(transParams)))

	// ParameterOffset: header(32) + WC(1) + words(20) + BC(2) + pad(1) = 56.
	const paramOffset = smb1HeaderSize + 1 + 20 + 2 + 1
	le.PutUint16(words[8:], paramOffset)

	le.PutUint16(words[12:], uint16(len(transData)))

	// DataOffset: after params, with alignment padding.
	dataOffset := paramOffset + len(transParams)
	dataPad := 0
	if len(transData) > 0 && dataOffset%2 != 0 {
		dataPad = 1
		dataOffset++
	}
	le.PutUint16(words[14:], uint16(dataOffset))
	resp.words = words

	// Data section: pad(1) + transParams + dataPad + transData.
	data := make([]byte, 1+len(transParams)+dataPad+len(transData))
	copy(data[1:], transParams)
	copy(data[1+len(transParams)+dataPad:], transData)
	resp.data = data

	return resp
}
