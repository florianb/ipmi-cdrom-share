// Package smbserver implements a minimal read-only SMB server that offers one
// file to guests. It speaks SMB1 (NT LM 0.12) and SMB 2.0.2 through 3.0.2.
package smbserver

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

// ErrUnknownProtocol reports a frame that is neither SMB1 nor SMB2.
var ErrUnknownProtocol = errors.New("unknown SMB protocol identifier")

type protocol int

const (
	protoSMB1 protocol = iota + 1
	protoSMB2
)

// identifyProtocol classifies a session message by its first four bytes.
func identifyProtocol(frame []byte) (protocol, error) {
	if len(frame) >= 4 {
		switch [4]byte(frame[:4]) {
		case [4]byte{0xFF, 'S', 'M', 'B'}:
			return protoSMB1, nil
		case [4]byte{0xFE, 'S', 'M', 'B'}:
			return protoSMB2, nil
		}
	}
	head := frame[:min(len(frame), 4)]
	return 0, fmt.Errorf("%w: % x (%d byte frame)", ErrUnknownProtocol, head, len(frame))
}

// Server serves one Share to any number of connections.
type Server struct {
	share      *Share
	serverGUID [16]byte
	progress   *progress
	debug      *debugStats // nil unless debug output is enabled
}

// NewServer returns a Server for share. With debug set it logs every SMB2
// command and prints performance statistics.
func NewServer(share *Share, debug bool) (*Server, error) {
	s := &Server{
		share: share,
		progress: &progress{
			fileSize:  share.Size(),
			fileName:  share.Name(),
			events:    make(chan readEvent, 4096),
			done:      make(chan struct{}),
			debugMode: debug,
		},
	}
	if _, err := rand.Read(s.serverGUID[:]); err != nil {
		return nil, fmt.Errorf("generate server GUID: %w", err)
	}
	if debug {
		s.debug = &debugStats{}
	}
	return s, nil
}

// Serve accepts connections until ctx is cancelled, then closes ln and all open
// connections and waits for their handlers. It returns nil after a shutdown
// requested through ctx. A Server can only serve once.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	stopListener := context.AfterFunc(ctx, func() { ln.Close() })
	defer stopListener()

	stopStats := s.startStats()
	var conns sync.WaitGroup
	defer func() {
		ln.Close()
		cancel()
		conns.Wait()
		stopStats()
	}()

	const maxAcceptDelay = time.Second
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return fmt.Errorf("accept: %w", err)
			}
			// Probably transient, such as running out of file descriptors.
			delay = min(max(2*delay, 5*time.Millisecond), maxAcceptDelay)
			log.Printf("Accept error: %v; retrying in %v", err, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil
			}
			continue
		}
		delay = 0
		conns.Add(1)
		go func() {
			defer conns.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// startStats starts the display goroutines and returns a function stopping them.
func (s *Server) startStats() (stop func()) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.progress.run()
	}()

	debugDone := make(chan struct{})
	if s.debug != nil {
		log.Printf("[debug] Performance tracing enabled (2s intervals)")
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.debug.runDebugDisplay(debugDone)
		}()
	}
	return func() {
		close(s.progress.done)
		close(debugDone)
		wg.Wait()
	}
}

// connState is the per-connection protocol state.
type connState struct {
	w      io.Writer
	remote string
	proto  protocol // set once a NEGOTIATE has fixed the protocol
	smb1   *session
	smb2   *smb2Conn
}

func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	remote := conn.RemoteAddr().String()

	// Disable Nagle's algorithm to avoid coalescing small writes.
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.SetNoDelay(true); err != nil {
			log.Printf("[%s] SetNoDelay: %v", remote, err)
		}
	}

	clientIP := remote
	if host, _, err := net.SplitHostPort(remote); err == nil {
		clientIP = host
	}

	log.Printf("[%s] Connected", remote)
	defer log.Printf("[%s] Disconnected", remote)

	s.progress.mu.Lock()
	s.progress.client = clientIP
	s.progress.mu.Unlock()

	c := &connState{
		w:      conn,
		remote: remote,
		smb1:   newSMB1Session(s),
		smb2:   newSMB2Conn(s, remote),
	}

	for {
		frame, msgType, err := readFrame(conn)
		if err != nil {
			if !isConnClosed(err) {
				log.Printf("[%s] Read error: %v", remote, err)
			}
			return
		}

		switch msgType {
		case frameTypeSessionMessage:
			if err := c.handleFrame(frame); err != nil {
				if !isConnClosed(err) {
					log.Printf("[%s] %v", remote, err)
				}
				return
			}
		case frameTypeSessionRequest: // port 139 compatibility
			if err := writeFrame(conn, frameTypePositiveSession, nil); err != nil {
				if !isConnClosed(err) {
					log.Printf("[%s] Write error: %v", remote, err)
				}
				return
			}
		}
	}
}

// isConnClosed reports whether err only says that the connection has ended.
func isConnClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe)
}

// handleFrame routes one session message by protocol. A returned error ends the
// connection.
func (c *connState) handleFrame(frame []byte) error {
	proto, err := identifyProtocol(frame)
	if err != nil {
		return err
	}

	switch proto {
	case protoSMB1:
		if c.proto == protoSMB2 {
			return fmt.Errorf("%w: SMB1 frame on SMB2 connection", errSMB2Protocol)
		}
		req, err := parseSMBPacket(frame)
		if err != nil {
			return fmt.Errorf("parse SMB1 packet: %w", err)
		}
		if req.header.command == smbComNegotiate {
			dialect := selectMultiProtocolDialect(req.data)
			if dialect != 0 {
				c.proto = protoSMB2
				return c.smb2.serveMultiProtocolNegotiate(c.w, dialect)
			}
			c.proto = protoSMB1
		}
		return c.smb1.serve(c.w, req)
	case protoSMB2:
		if c.proto == protoSMB1 {
			return fmt.Errorf("%w: SMB2 frame on SMB1 connection", errSMB2Protocol)
		}
		c.proto = protoSMB2
		return c.smb2.serveFrame(c.w, frame)
	}
	return nil
}
