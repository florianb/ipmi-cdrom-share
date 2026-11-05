// Command ipmi-cdrom-share serves a single read-only ISO image over SMB for
// IPMI/BMC virtual media clients.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
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
	if err := run(os.Args[1:]); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, err)
			printUsage()
			os.Exit(2)
		}
		log.Fatal(err)
	}
}

// usageError marks a command line mistake, as opposed to a runtime failure.
type usageError string

// Error returns the message shown to the user.
func (e usageError) Error() string { return string(e) }

// printUsage writes the command line help to stderr.
func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [--debug] <iso-path> [listen-addr]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Default listen address: %s\n", defaultListenAddr)
	fmt.Fprintln(os.Stderr, "Flags must come before the ISO path.")
}

// run parses args, the command line without the program name, and serves the
// file until SIGINT or SIGTERM arrives.
func run(args []string) error {
	// Errors go through main like every other usage error, so the flag package
	// must not print anything itself.
	flags := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {}
	debug := flags.Bool("debug", false, "log every SMB2 command and print performance statistics")
	switch err := flags.Parse(args); {
	case errors.Is(err, flag.ErrHelp):
		printUsage()
		return nil
	case err != nil:
		return usageError(err.Error())
	}

	positional := flags.Args()
	for _, a := range positional {
		if strings.HasPrefix(a, "-") {
			return usageError(fmt.Sprintf("flag %q must come before the ISO path", a))
		}
	}
	if len(positional) < 1 || len(positional) > 2 {
		return usageError("expected an ISO path and an optional listen address")
	}
	listenAddr := defaultListenAddr
	if len(positional) == 2 {
		listenAddr = positional[1]
	}

	share, err := smbserver.OpenShare(positional[0])
	if err != nil {
		return err
	}
	defer share.Close()

	srv, err := smbserver.NewServer(share, smbserver.Options{Debug: *debug})
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
