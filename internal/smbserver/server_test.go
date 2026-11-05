package smbserver

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Protocol detection ---

func TestIdentifyProtocol(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		want    protocol
		wantErr string
	}{
		{"smb1", []byte("\xFFSMB\x72"), protoSMB1, ""},
		{"smb2", []byte("\xFESMB\x40"), protoSMB2, ""},
		{"encrypted", []byte("\xFDSMB\x00"), 0, "fd 53 4d 42"},
		{"garbage", []byte{1, 2, 3, 4, 5}, 0, "01 02 03 04"},
		{"short", []byte{0xFE}, 0, "fe (1 byte frame)"},
		{"empty", nil, 0, "(0 byte frame)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := identifyProtocol(tt.frame)
			if got != tt.want {
				t.Errorf("protocol = %v, want %v", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrUnknownProtocol) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want ErrUnknownProtocol containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestUnknownProtocolDropsConnection(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	c.sendFrame([]byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0})
	if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
		t.Fatalf("read after unknown frame: %v, want EOF", err)
	}
}

func TestProtocolSwitchDropsConnection(t *testing.T) {
	t.Run("smb1 after smb2", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.call(smb2Negotiate, negotiateBody(0x0210))
		c.sendFrame(smb1Negotiate("NT LM 0.12"))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
	t.Run("smb2 after smb1", func(t *testing.T) {
		c := dialPipe(t, newTestServer(t, nil))
		c.sendFrame(smb1Negotiate("NT LM 0.12"))
		c.recvFrame()
		c.sendFrame(encodeRequest(smb2Msg{command: smb2Negotiate, body: negotiateBody(0x0210)}))
		if _, _, err := readFrame(c.conn); !errors.Is(err, io.EOF) {
			t.Errorf("read: %v, want EOF", err)
		}
	})
}

func TestSessionRequestFrame(t *testing.T) {
	c := dialPipe(t, newTestServer(t, nil))
	if err := writeFrame(c.conn, frameTypeSessionRequest, []byte("names")); err != nil {
		t.Fatal(err)
	}
	if _, msgType, err := readFrame(c.conn); err != nil || msgType != frameTypePositiveSession {
		t.Errorf("type %#x, err %v", msgType, err)
	}
}

// --- Lifecycle ---

func TestServeShutdown(t *testing.T) {
	srv := newTestServer(t, testContent(10))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ctx, ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, frameTypeSessionMessage, encodeRequest(smb2Msg{command: smb2Negotiate, body: negotiateBody(0x0302)})); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFrame(conn); err != nil {
		t.Fatal(err)
	}

	cancel()
	select {
	case err := <-serveErr:
		if err != nil {
			t.Errorf("Serve returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
	if _, _, err := readFrame(conn); err == nil {
		t.Error("connection still open after shutdown")
	}
}

func TestServeListenerClosedExternally(t *testing.T) {
	srv := newTestServer(t, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(context.Background(), ln) }()
	ln.Close()
	select {
	case err := <-serveErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("Serve returned %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve kept running on a closed listener")
	}
}

func TestOpenShareRejectsDirectory(t *testing.T) {
	if _, err := OpenShare(t.TempDir()); err == nil {
		t.Error("expected an error for a directory")
	}
	if _, err := OpenShare(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

func TestFormatting(t *testing.T) {
	for _, tt := range []struct {
		size int64
		want string
	}{
		{0, "0 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1<<20 - 1, "1024.0 KB"},
		{1 << 20, "1.0 MB"},
		{1 << 30, "1.0 GB"},
		{5<<30 + 1<<29, "5.5 GB"},
		{-5, "-5 B"},
	} {
		if got := FormatSize(tt.size); got != tt.want {
			t.Errorf("FormatSize(%d) = %q, want %q", tt.size, got, tt.want)
		}
	}
	for _, tt := range []struct {
		speed float64
		want  string
	}{
		{0, "0 B/s"},
		{1023.4, "1023 B/s"},
		{1024, "1.0 KB/s"},
		{1 << 20, "1.0 MB/s"},
		{3 << 30, "3.0 GB/s"},
	} {
		if got := formatSpeed(tt.speed); got != tt.want {
			t.Errorf("formatSpeed(%v) = %q, want %q", tt.speed, got, tt.want)
		}
	}
	for _, tt := range []struct {
		count int64
		want  string
	}{
		{0, "0"},
		{999, "999"},
		{1000, "1,000"},
		{1204, "1,204"},
		{1234567, "1,234,567"},
	} {
		if got := formatCount(tt.count); got != tt.want {
			t.Errorf("formatCount(%d) = %q, want %q", tt.count, got, tt.want)
		}
	}
}
