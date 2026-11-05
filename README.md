# ipmi-cdrom-share

Serve an ISO over SMB for IPMI/BMC virtual media. Single binary, zero config, no dependencies beyond the Go standard library.

BMC virtual media clients often speak only one old SMB dialect: many (Supermicro, Dell iDRAC, HP iLO) only support SMB1, others only a single SMB 3.x version. Running a full Samba install to share one read-only file is overkill. This does the minimum needed and supports SMB1 (NT LM 0.12) and SMB 2.0.2, 2.1, 3.0 and 3.0.2.

## Quick Start

```bash
go build -o ipmi-cdrom-share .
sudo ./ipmi-cdrom-share /path/to/TrueNAS-SCALE-25.10.1.iso
```

In your BMC virtual media settings:

| Field | Value |
|-------|-------|
| Share Host | `192.168.1.x` (your server IP) |
| Share Name | `share` |
| Path to Image | `TrueNAS-SCALE-25.10.1.iso` |
| User | *(blank)* |
| Password | *(blank)* |

Or as a UNC path: `\\192.168.1.x\share\TrueNAS-SCALE-25.10.1.iso`

## Usage

```
sudo ./ipmi-cdrom-share [--debug] <iso-path> [listen-addr]
```

Flags must come before the ISO path. `--debug` logs every SMB2 command and prints performance statistics.

Port 445 is the default and requires root. Alternatives:

```bash
# Custom port (if your BMC supports non-standard ports)
sudo ./ipmi-cdrom-share /path/to/file.iso :8445

# Bind to specific interface
sudo ./ipmi-cdrom-share /path/to/file.iso 192.168.1.100:445

# Use setcap instead of root
sudo setcap cap_net_bind_service=+ep ./ipmi-cdrom-share
./ipmi-cdrom-share /path/to/file.iso
```

## How It Works

The first four bytes of each frame select the protocol. An SMB1 NEGOTIATE that offers `NT LM 0.12` stays on SMB1; one that offers only `SMB 2.???` or `SMB 2.002` is upgraded to SMB2.

**SMB1** implements the bare minimum of CIFS to satisfy BMC virtual media clients:

1. **NEGOTIATE** — Selects the "NT LM 0.12" dialect
2. **SESSION_SETUP** — Accepts any credentials as guest
3. **TREE_CONNECT** — Accepts any share name
4. **NT_CREATE** — Opens the ISO file, returns its size
5. **READ** — Serves file data with 64-bit offset support (ISOs > 4GB)
6. **CLOSE / DISCONNECT / LOGOFF** — Cleans up

**SMB2/3** follows the same idea:

1. **NEGOTIATE** — Selects the simplest dialect offered, in the order 2.1, 2.0.2, 3.0.2, 3.0
2. **SESSION_SETUP** — Runs an NTLMSSP exchange (raw or in SPNEGO) without checking anything and logs the client in as guest
3. **TREE_CONNECT** — Treats `IPC$` as a pipe share and any other name as the disk share
4. **CREATE / QUERY_INFO / QUERY_DIRECTORY / READ / CLOSE** — Read-only access to the one file, including compound requests
5. **IOCTL** — Answers `FSCTL_VALIDATE_NEGOTIATE_INFO`

Limits: no password checks, encryption or write support. SMB 3.1.1, signing, multichannel and large MTU are not implemented, so reads are capped at 64 KiB. A client that refuses unsigned guest sessions cannot connect.

## Testing

```bash
go vet ./...
go test -race ./...

# Fuzz the parsers and command handlers
go test -run='^$' -fuzz=FuzzSMB2ServeFrame -fuzztime=1m ./internal/smbserver
go test -run='^$' -fuzz=FuzzSMB1Dispatch -fuzztime=1m ./internal/smbserver
```

### Acceptance tests

The tests in `acceptance/` build the real binary, start it on a free local port and talk to it from the outside. They use [go-smb2](https://github.com/hirochachacha/go-smb2) as an independent client and cover downloads over all four dialects, reads above 4 GiB, read-only behaviour, concurrent clients, shutdown on SIGTERM and exit codes. They are a separate Go module, so `go test ./...` in the main module does not run them:

```bash
(cd acceptance && go test -race ./...)
```

### SMB1 wire format

go-smb2 does not speak SMB1. `TestSMB1WireFormat` therefore runs the BMC sequence and every handler branch and compares each response byte for byte with `internal/smbserver/testdata/smb1_wire.golden`; only timestamps are masked. BMC firmware is picky, so this file must only change together with a deliberate wire format change:

```bash
go test -run=TestSMB1WireFormat ./internal/smbserver -args -update-smb1-wire
```

### Manual tests

With a real client, on a test port:

```bash
./ipmi-cdrom-share /tmp/test.iso 127.0.0.1:1445

# SMB 2.0.2 to 3.0.2: set the dialect to SMB2_02, SMB2_10, SMB3_00 or SMB3_02
smbclient //127.0.0.1/share -p 1445 -N \
  --option='client min protocol=SMB3_02' --option='client max protocol=SMB3_02' \
  -c 'ls; get test.iso /tmp/out.iso'
sha256sum /tmp/test.iso /tmp/out.iso

# Linux kernel client on port 445, with vers=2.1, 3.0 or 3.02
sudo mount -t cifs //localhost/share /mnt -o vers=3.02,guest,ro
sha256sum /path/to/original.iso /mnt/original.iso
```

`smbclient` (checked with 4.19) cannot test the SMB1 path: it rejects the SMB1 NEGOTIATE response with `NT_STATUS_INVALID_PARAMETER`. `TestE2ESMB1` and `TestSMB1WireFormat` cover this path instead, but only with the project's own test client.

## Tested BMCs

- Supermicro X11/X12 series IPMI

## Building

Requires Go 1.22+. The binary and the main module have no external dependencies; only the separate test module in `acceptance/` requires go-smb2.

```bash
go build -o ipmi-cdrom-share .
```

Cross-compile for a different server:

```bash
GOOS=linux GOARCH=amd64 go build -o ipmi-cdrom-share .
```

## License

MIT
