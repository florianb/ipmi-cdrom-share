// Package smbserver implements a minimal read-only SMB server that offers one
// file to guests. It speaks SMB1 (NT LM 0.12) and SMB 2.0.2 through 3.0.2, because
// BMC virtual media firmware often knows only one old dialect.
//
// # Protocol selection
//
// The first four bytes of a message select the protocol (see identifyProtocol). An
// SMB1 NEGOTIATE offering "NT LM 0.12" stays on SMB1, even if it offers SMB2 too:
// the SMB1 path is the one tested against real boards. One offering only "SMB 2.???"
// or "SMB 2.002" is answered with an SMB2 NEGOTIATE response ([MS-SMB2] 3.3.5.3).
// Once a NEGOTIATE has fixed the protocol, a frame of the other one ends the
// connection.
//
// # Connection lifecycle
//
// Server.Serve runs one goroutine per connection. Each reads frames (transport.go)
// and hands them to handleFrame, which passes them to smb1Session or smb2Conn. Both
// follow the same pattern: a dispatcher finds the handler, the handler returns a
// response and an ntStatus, and the dispatcher turns a failure into the error
// response. A handler answers errors with a status; a connection only ends on a
// failed write or when a client breaks the framing or the protocol
// (errProtocolViolation).
//
// # Concurrency
//
// All protocol state belongs to the goroutine of its connection and needs no locks.
// What connections share is safe for concurrent use: Share only offers ReadAt, the
// debug statistics are atomic, and progress receives its events over a channel that
// never blocks a reader, dropping events instead. Read responses use pooled buffers
// (readBufPool), so a transfer does not allocate one buffer per read.
//
// # Deliberate limits
//
//   - Logons are not checked. Everyone is a guest, which is why no session key
//     exists and messages are neither signed nor encrypted. A client that refuses
//     unsigned guest sessions cannot connect.
//   - SMB 3.1.1 is not offered: it requires negotiate contexts.
//   - Multichannel and large MTU are not implemented, so reads are capped at 64 KiB.
//   - Nothing can be written. Requests that would modify anything fail.
//
// # Wire format
//
// Messages are read and written through explicit offsets instead of structs: this
// keeps the read path free of allocations and the code comparable with the
// specification, whose tables list the same offsets. Handler comments name the
// message and the fields they use. Offsets of SMB2 fields are relative to the body
// after the 64-byte header, those of SMB1 fields to the parameter words.
//
// # Specifications
//
//   - [MS-SMB2]: Server Message Block Protocol Versions 2 and 3
//   - [MS-CIFS]: Common Internet File System Protocol, the base of SMB1, and
//     [MS-SMB]: its extensions
//   - [MS-NLMP]: NT LAN Manager Authentication Protocol
//   - [MS-FSCC]: File System Control Codes, with the information classes in
//     sections 2.4 and 2.5
//   - [MS-ERREF]: Windows Error Codes
//   - RFC 1002: NetBIOS session service, the frame format on port 139
//   - RFC 4178: SPNEGO
package smbserver
