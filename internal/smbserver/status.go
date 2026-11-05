package smbserver

// ntStatus is an NTSTATUS code, the result of a request in both SMB1 and SMB2.
// The top two bits give the severity: 0x8 is a warning, 0xC an error. Values are
// defined in [MS-ERREF] 2.3.
type ntStatus uint32

// NT status codes used by the server.
const (
	statusOK                     ntStatus = 0x00000000
	statusBufferOverflow         ntStatus = 0x80000005
	statusNoMoreFiles            ntStatus = 0x80000006
	statusNotImplemented         ntStatus = 0xC0000002
	statusInvalidInfoClass       ntStatus = 0xC0000003
	statusInfoLengthMismatch     ntStatus = 0xC0000004
	statusInvalidHandle          ntStatus = 0xC0000008
	statusInvalidParameter       ntStatus = 0xC000000D
	statusNoSuchFile             ntStatus = 0xC000000F
	statusInvalidDeviceRequest   ntStatus = 0xC0000010
	statusEndOfFile              ntStatus = 0xC0000011
	statusMoreProcessingRequired ntStatus = 0xC0000016
	statusAccessDenied           ntStatus = 0xC0000022
	statusBufferTooSmall         ntStatus = 0xC0000023
	statusObjectNameNotFound     ntStatus = 0xC0000034
	statusObjectNameCollision    ntStatus = 0xC0000035
	statusLogonFailure           ntStatus = 0xC000006D
	statusInsufficientResources  ntStatus = 0xC000009A
	statusFileIsADirectory       ntStatus = 0xC00000BA
	statusNotSupported           ntStatus = 0xC00000BB
	statusNetworkNameDeleted     ntStatus = 0xC00000C9
	statusRequestNotAccepted     ntStatus = 0xC00000D0
	statusUnexpectedIOError      ntStatus = 0xC00000E9
	statusNotADirectory          ntStatus = 0xC0000103
	statusFileClosed             ntStatus = 0xC0000128
	statusFSDriverRequired       ntStatus = 0xC000019C
	statusUserSessionDeleted     ntStatus = 0xC0000203
)

// hasBody reports whether an SMB2 response with this status keeps its regular body
// instead of the error body. BUFFER_OVERFLOW and MORE_PROCESSING_REQUIRED are not
// real failures: the body holds the truncated data and the next logon step.
func (s ntStatus) hasBody() bool {
	return s == statusOK || s == statusMoreProcessingRequired || s == statusBufferOverflow
}
