// Package acceptance tests the real ipmi-cdrom-share binary from the outside,
// with go-smb2 as an independent SMB2/3 client. It is a separate module so that
// the client library never becomes a dependency of the server.
package acceptance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"
)

const (
	imageName = "accept.iso"
	timeout   = 60 * time.Second
)

// binary is the path of the server built by TestMain.
var binary string

func TestMain(m *testing.M) {
	os.Exit(buildAndRun(m))
}

func buildAndRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "ipmi-cdrom-share-acceptance")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "ipmi-cdrom-share")
	build := exec.Command("go", "build", "-o", binary, ".")
	build.Dir = ".."
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// server is a running server process. Its output is shown only for failed tests.
type server struct {
	cmd    *exec.Cmd
	addr   string
	output *bytes.Buffer
	waited chan error
}

// startServer runs the binary on a free local port and waits until it accepts
// connections.
func startServer(t *testing.T, image string) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	s := &server{
		cmd:    exec.Command(binary, image, addr),
		addr:   addr,
		output: new(bytes.Buffer),
		waited: make(chan error, 1),
	}
	s.cmd.Stdout = s.output
	s.cmd.Stderr = s.output
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { s.waited <- s.cmd.Wait() }()
	t.Cleanup(func() {
		s.cmd.Process.Kill()
		if t.Failed() {
			t.Logf("server output:\n%s", s.output)
		}
	})

	deadline := time.Now().Add(timeout)
	for {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("server not ready: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// mount logs in as guest with a fixed dialect (0 lets the client offer all it
// knows) and mounts the share.
func mount(t *testing.T, addr string, dialect uint16) *smb2.Share {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}

	dialer := &smb2.Dialer{
		Negotiator: smb2.Negotiator{SpecifiedDialect: dialect},
		Initiator:  &smb2.NTLMInitiator{User: "Guest"},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	session, err := dialer.DialContext(ctx, conn)
	if err != nil {
		t.Fatalf("session setup: %v", err)
	}
	t.Cleanup(func() { session.Logoff() })

	share, err := session.WithContext(ctx).Mount("share")
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	t.Cleanup(func() { share.Umount() })
	return share.WithContext(ctx)
}

// writeImage creates an image with reproducible pseudo-random content.
func writeImage(t *testing.T, size int) (path string, content []byte) {
	t.Helper()
	content = make([]byte, size)
	rand.New(rand.NewSource(1)).Read(content)
	path = filepath.Join(t.TempDir(), imageName)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, content
}

// TestDownload lists and downloads the file over every supported dialect.
func TestDownload(t *testing.T) {
	path, content := writeImage(t, 5<<20+1234)
	s := startServer(t, path)

	for _, tt := range []struct {
		name    string
		dialect uint16
	}{
		{"2.0.2", 0x0202},
		{"2.1", 0x0210},
		{"3.0", 0x0300},
		{"3.0.2", 0x0302},
	} {
		t.Run(tt.name, func(t *testing.T) {
			share := mount(t, s.addr, tt.dialect)

			entries, err := share.ReadDir(".")
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 1 || entries[0].Name() != imageName || entries[0].Size() != int64(len(content)) {
				t.Fatalf("ReadDir: %d entries: %v", len(entries), entries)
			}

			f, err := share.Open(imageName)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			defer f.Close()
			h := sha256.New()
			n, err := io.Copy(h, f)
			if err != nil {
				t.Fatalf("download: %v", err)
			}
			if n != int64(len(content)) || [32]byte(h.Sum(nil)) != sha256.Sum256(content) {
				t.Errorf("downloaded %d bytes with a different hash, want %d", n, len(content))
			}
		})
	}
}

// TestReadAboveFourGiB reads across the 32-bit offset limit of a sparse file.
func TestReadAboveFourGiB(t *testing.T) {
	const (
		size   = 5 << 30
		offset = 4<<30 + 12345
	)
	marker := []byte("beyond the 32-bit limit")
	path := filepath.Join(t.TempDir(), imageName)
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(size); err != nil {
		t.Skipf("no sparse file support: %v", err)
	}
	if _, err := f.WriteAt(marker, offset); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	share := mount(t, startServer(t, path).addr, 0x0302)
	remote, err := share.Open(imageName)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer remote.Close()

	info, err := remote.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() != size {
		t.Errorf("size %d, want %d", info.Size(), size)
	}
	got := make([]byte, len(marker))
	if _, err := remote.ReadAt(got, offset); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if !bytes.Equal(got, marker) {
		t.Errorf("read %q, want %q", got, marker)
	}
}

// TestReadOnly checks that no client operation changes the file.
func TestReadOnly(t *testing.T) {
	path, content := writeImage(t, 4096)
	share := mount(t, startServer(t, path).addr, 0x0302)

	if f, err := share.OpenFile(imageName, os.O_RDWR, 0); err == nil {
		f.Close()
		t.Error("opening for writing succeeded")
	}
	if f, err := share.Create("new.iso"); err == nil {
		f.Close()
		t.Error("creating a file succeeded")
	}
	if err := share.Remove(imageName); err == nil {
		t.Error("removing the file succeeded")
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, content) {
		t.Error("file changed on disk")
	}
}

// TestUnknownFile checks that other names do not exist.
func TestUnknownFile(t *testing.T) {
	path, _ := writeImage(t, 16)
	share := mount(t, startServer(t, path).addr, 0x0302)

	_, err := share.Open("other.iso")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open: %v, want os.ErrNotExist", err)
	}
}

// TestConcurrentClients downloads over several connections at the same time.
func TestConcurrentClients(t *testing.T) {
	path, content := writeImage(t, 2<<20)
	s := startServer(t, path)
	want := sha256.Sum256(content)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		share := mount(t, s.addr, 0x0302)
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := share.ReadFile(imageName)
			if err != nil {
				t.Errorf("ReadFile: %v", err)
			} else if sha256.Sum256(got) != want {
				t.Error("concurrent download has a different hash")
			}
		}()
	}
	wg.Wait()
}

// TestGracefulShutdown checks that SIGTERM ends the process cleanly while a
// client is connected.
func TestGracefulShutdown(t *testing.T) {
	path, _ := writeImage(t, 16)
	s := startServer(t, path)
	mount(t, s.addr, 0x0302)

	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-s.waited:
		if err != nil {
			t.Errorf("exit after SIGTERM: %v, want exit code 0", err)
		}
	case <-time.After(timeout):
		t.Fatal("process did not exit after SIGTERM")
	}
}

// TestUsageError checks the exit code of command line mistakes.
func TestUsageError(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
	}{
		{"no arguments", nil},
		{"too many arguments", []string{"a.iso", ":1445", "extra"}},
		{"flag after path", []string{"a.iso", "--debug"}},
		{"unknown flag", []string{"--nope", "a.iso"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := exec.Command(binary, tt.args...).Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 2 {
				t.Errorf("result %v, want exit code 2", err)
			}
		})
	}
}
