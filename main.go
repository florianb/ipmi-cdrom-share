// Command ipmi-cdrom-share serves a single read-only ISO image over SMB for
// IPMI/BMC virtual media clients.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"ipmi-cdrom-share/internal/smbserver"
)

const defaultListenAddr = ":445"

func main() {
	if err := run(); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, err)
			flag.Usage()
			os.Exit(2)
		}
		log.Fatal(err)
	}
}

// usageError marks a command line mistake, as opposed to a runtime failure.
type usageError string

func (e usageError) Error() string { return string(e) }

func run() error {
	debug := flag.Bool("debug", false, "log every SMB2 command and print performance statistics")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [--debug] <iso-path> [listen-addr]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Default listen address: %s\n", defaultListenAddr)
		fmt.Fprintln(os.Stderr, "Flags must come before the ISO path.")
	}
	flag.Parse()

	args := flag.Args()
	for _, a := range args {
		if strings.HasPrefix(a, "-") {
			return usageError(fmt.Sprintf("flag %q must come before the ISO path", a))
		}
	}
	if len(args) < 1 || len(args) > 2 {
		return usageError("expected an ISO path and an optional listen address")
	}
	listenAddr := defaultListenAddr
	if len(args) == 2 {
		listenAddr = args[1]
	}

	share, err := smbserver.OpenShare(args[0])
	if err != nil {
		return err
	}
	defer share.Close()

	srv, err := smbserver.NewServer(share, *debug)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("Serving %s (%s) on smb://%s/share/%s",
		share.Name(), smbserver.FormatSize(share.Size()), listenAddr, share.Name())
	return srv.Serve(ctx, ln)
}
