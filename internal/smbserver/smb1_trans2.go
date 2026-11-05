package smbserver

import (
	"encoding/binary"
	"log"
	"strings"
	"time"
)

// --- TRANSACTION2 (0x32) ---

func handleTrans2(sess *session, req *smbPacket) *smbPacket {
	if len(req.words) < 28 {
		return errorResponse(req, statusNotImplemented)
	}

	setupCount := int(req.words[26])
	if setupCount < 1 || len(req.words) < 28+setupCount*2 {
		return errorResponse(req, statusNotImplemented)
	}
	subcommand := binary.LittleEndian.Uint16(req.words[28:30])

	paramCount := int(binary.LittleEndian.Uint16(req.words[18:20]))
	paramOffset := int(binary.LittleEndian.Uint16(req.words[20:22]))

	// Convert paramOffset (from SMB header start) to data section offset.
	headerLen := 32 + 1 + len(req.words) + 2
	transParamStart := paramOffset - headerLen
	var transParams []byte
	if transParamStart >= 0 && transParamStart+paramCount <= len(req.data) {
		transParams = req.data[transParamStart : transParamStart+paramCount]
	} else if transParamStart >= 0 && transParamStart < len(req.data) {
		transParams = req.data[transParamStart:]
	}

	switch subcommand {
	case trans2FindFirst2:
		return handleFindFirst2(sess, req, transParams)
	case trans2QueryFSInfo:
		return handleQueryFSInfo(sess, req, transParams)
	case trans2QueryPathInfo:
		return handleQueryPathInfo(sess, req, transParams)
	case trans2QueryFileInfo:
		return handleQueryFileInfo(sess, req, transParams)
	default:
		log.Printf("Unhandled TRANS2 subcommand: 0x%04X", subcommand)
		return errorResponse(req, statusNotImplemented)
	}
}

func handleQueryFSInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 2 {
		return errorResponse(req, statusNotImplemented)
	}
	infoLevel := binary.LittleEndian.Uint16(transParams[0:2])
	log.Printf("QUERY_FS_INFO level=0x%04X", infoLevel)

	var infoData []byte

	switch infoLevel {
	case smbQueryFSSizeInfo:
		// TotalUnits(8) + FreeUnits(8) + SectorsPerUnit(4) + BytesPerSector(4)
		infoData = make([]byte, 24)
		totalUnits := uint64(sess.fileSize) / 4096
		binary.LittleEndian.PutUint64(infoData[0:8], totalUnits)
		// FreeUnits = 0 (read-only)
		binary.LittleEndian.PutUint32(infoData[16:20], 8)   // sectors per unit
		binary.LittleEndian.PutUint32(infoData[20:24], 512) // bytes per sector

	case smbQueryFSDeviceInfo:
		// DeviceType(4) + Characteristics(4)
		infoData = make([]byte, 8)
		binary.LittleEndian.PutUint32(infoData[0:4], 0x00000007) // FILE_DEVICE_DISK
		binary.LittleEndian.PutUint32(infoData[4:8], 0x00000020) // READ_ONLY_DEVICE

	case smbQueryFSAttributeInfo:
		// Attributes(4) + MaxNameLen(4) + FSNameLen(4) + FSName
		fsName := encodeUTF16LE("FAT")
		infoData = make([]byte, 12+len(fsName))
		binary.LittleEndian.PutUint32(infoData[0:4], 0x0001) // CASE_SENSITIVE_SEARCH
		binary.LittleEndian.PutUint32(infoData[4:8], 255)
		binary.LittleEndian.PutUint32(infoData[8:12], uint32(len(fsName)))
		copy(infoData[12:], fsName)

	default:
		log.Printf("Unhandled FS info level: 0x%04X", infoLevel)
		return errorResponse(req, statusNotImplemented)
	}

	return buildTrans2Response(req, nil, infoData)
}

func handleQueryPathInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 6 {
		return errorResponse(req, statusNotImplemented)
	}

	infoLevel := binary.LittleEndian.Uint16(transParams[0:2])
	pathBytes := transParams[6:]

	var path string
	if sess.unicode {
		path = decodeUTF16LE(pathBytes)
	} else {
		path = strings.TrimRight(string(pathBytes), "\x00")
	}
	path = strings.TrimPrefix(path, "\\")

	log.Printf("QUERY_PATH_INFO level=0x%04X path=%q", infoLevel, path)

	if path == "" {
		return buildFileInfoResponse(req, infoLevel, true, 0)
	}
	if strings.EqualFold(path, sess.fileName) {
		return buildFileInfoResponse(req, infoLevel, false, sess.fileSize)
	}
	return errorResponse(req, statusObjectNameNotFound)
}

func handleQueryFileInfo(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 4 {
		return errorResponse(req, statusNotImplemented)
	}

	fid := binary.LittleEndian.Uint16(transParams[0:2])
	infoLevel := binary.LittleEndian.Uint16(transParams[2:4])

	log.Printf("QUERY_FILE_INFO fid=0x%04X level=0x%04X", fid, infoLevel)

	if fid == sess.fid {
		return buildFileInfoResponse(req, infoLevel, false, sess.fileSize)
	}
	return buildFileInfoResponse(req, infoLevel, true, 0)
}

func buildFileInfoResponse(req *smbPacket, infoLevel uint16, isDir bool, size int64) *smbPacket {
	now := timeToFiletime(time.Now())
	attr := uint32(fileAttrReadOnly)
	if isDir {
		attr = fileAttrDirectory
	}

	var infoData []byte

	switch infoLevel {
	case smbQueryFileBasicInfo:
		infoData = make([]byte, 40)
		binary.LittleEndian.PutUint64(infoData[0:8], now)
		binary.LittleEndian.PutUint64(infoData[8:16], now)
		binary.LittleEndian.PutUint64(infoData[16:24], now)
		binary.LittleEndian.PutUint64(infoData[24:32], now)
		binary.LittleEndian.PutUint32(infoData[32:36], attr)

	case smbQueryFileStandardInfo:
		infoData = make([]byte, 22)
		binary.LittleEndian.PutUint64(infoData[0:8], uint64(size))
		binary.LittleEndian.PutUint64(infoData[8:16], uint64(size))
		binary.LittleEndian.PutUint32(infoData[16:20], 1)
		if isDir {
			infoData[21] = 1
		}

	case smbQueryFileAllInfo:
		infoData = make([]byte, 72)
		binary.LittleEndian.PutUint64(infoData[0:8], now)
		binary.LittleEndian.PutUint64(infoData[8:16], now)
		binary.LittleEndian.PutUint64(infoData[16:24], now)
		binary.LittleEndian.PutUint64(infoData[24:32], now)
		binary.LittleEndian.PutUint32(infoData[32:36], attr)
		// Pad at 36:40
		binary.LittleEndian.PutUint64(infoData[40:48], uint64(size))
		binary.LittleEndian.PutUint64(infoData[48:56], uint64(size))
		binary.LittleEndian.PutUint32(infoData[56:60], 1) // NumberOfLinks
		if isDir {
			infoData[61] = 1
		}
		// EaSize(4) at 64, FileNameLength(4) at 68 = 0

	default:
		return errorResponse(req, statusNotImplemented)
	}

	return buildTrans2Response(req, nil, infoData)
}

func handleFindFirst2(sess *session, req *smbPacket, transParams []byte) *smbPacket {
	if len(transParams) < 12 {
		return errorResponse(req, statusNotImplemented)
	}

	infoLevel := binary.LittleEndian.Uint16(transParams[6:8])
	patternBytes := transParams[12:]

	var pattern string
	if sess.unicode {
		pattern = decodeUTF16LE(patternBytes)
	} else {
		pattern = strings.TrimRight(string(patternBytes), "\x00")
	}
	log.Printf("FIND_FIRST2 level=0x%04X pattern=%q", infoLevel, pattern)

	now := timeToFiletime(time.Now())
	var nameBytes []byte
	if sess.unicode {
		nameBytes = encodeUTF16LE(sess.fileName)
	} else {
		nameBytes = []byte(sess.fileName)
	}

	var entryData []byte

	switch infoLevel {
	case smbFindFileBothDirInfo:
		entryData = make([]byte, 94+len(nameBytes))
		// NextEntryOffset(4)=0, FileIndex(4)=0
		binary.LittleEndian.PutUint64(entryData[8:16], now)
		binary.LittleEndian.PutUint64(entryData[16:24], now)
		binary.LittleEndian.PutUint64(entryData[24:32], now)
		binary.LittleEndian.PutUint64(entryData[32:40], now)
		binary.LittleEndian.PutUint64(entryData[40:48], uint64(sess.fileSize))
		binary.LittleEndian.PutUint64(entryData[48:56], uint64(sess.fileSize))
		binary.LittleEndian.PutUint32(entryData[56:60], fileAttrReadOnly)
		binary.LittleEndian.PutUint32(entryData[60:64], uint32(len(nameBytes)))
		// EaSize(4)=0, ShortNameLength(1)=0, Reserved(1)=0, ShortName(24)=zeros
		copy(entryData[94:], nameBytes)

	default:
		// FILE_DIRECTORY_INFO fallback.
		entryData = make([]byte, 64+len(nameBytes))
		binary.LittleEndian.PutUint64(entryData[8:16], now)
		binary.LittleEndian.PutUint64(entryData[16:24], now)
		binary.LittleEndian.PutUint64(entryData[24:32], now)
		binary.LittleEndian.PutUint64(entryData[32:40], now)
		binary.LittleEndian.PutUint64(entryData[40:48], uint64(sess.fileSize))
		binary.LittleEndian.PutUint64(entryData[48:56], uint64(sess.fileSize))
		binary.LittleEndian.PutUint32(entryData[56:60], fileAttrReadOnly)
		binary.LittleEndian.PutUint32(entryData[60:64], uint32(len(nameBytes)))
		copy(entryData[64:], nameBytes)
	}

	// FIND_FIRST2 response parameters.
	respParams := make([]byte, 10)
	binary.LittleEndian.PutUint16(respParams[0:2], 0x0001) // SID
	binary.LittleEndian.PutUint16(respParams[2:4], 1)      // SearchCount
	binary.LittleEndian.PutUint16(respParams[4:6], 1)      // EndOfSearch
	return buildTrans2Response(req, respParams, entryData)
}

func buildTrans2Response(req *smbPacket, transParams, transData []byte) *smbPacket {
	if transParams == nil {
		transParams = []byte{}
	}
	if transData == nil {
		transData = []byte{}
	}

	resp := newResponse(req)

	// WordCount = 10 (20 bytes).
	words := make([]byte, 20)
	binary.LittleEndian.PutUint16(words[0:2], uint16(len(transParams)))
	binary.LittleEndian.PutUint16(words[2:4], uint16(len(transData)))
	binary.LittleEndian.PutUint16(words[6:8], uint16(len(transParams)))

	// ParameterOffset: header(32) + WC(1) + words(20) + BC(2) + pad(1) = 56.
	paramOffset := 56
	binary.LittleEndian.PutUint16(words[8:10], uint16(paramOffset))

	binary.LittleEndian.PutUint16(words[12:14], uint16(len(transData)))

	// DataOffset: after params, with alignment padding.
	dataOffset := paramOffset + len(transParams)
	dataPad := 0
	if len(transData) > 0 && dataOffset%2 != 0 {
		dataPad = 1
		dataOffset++
	}
	binary.LittleEndian.PutUint16(words[14:16], uint16(dataOffset))
	resp.words = words

	// Data section: pad(1) + transParams + dataPad + transData.
	data := make([]byte, 1+len(transParams)+dataPad+len(transData))
	data[0] = 0x00 // alignment pad
	copy(data[1:1+len(transParams)], transParams)
	copy(data[1+len(transParams)+dataPad:], transData)
	resp.data = data

	return resp
}
