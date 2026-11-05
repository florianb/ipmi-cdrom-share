package smbserver

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

const (
	progressInterval      = 250 * time.Millisecond
	progressDebugInterval = 2 * time.Second

	// speedWindowSize is how far back the displayed speed looks.
	speedWindowSize = 2 * time.Second
	// minSpeedElapsed keeps the speed sane while the window holds a single sample.
	minSpeedElapsed = 0.25 // seconds
)

// readEvent is sent from the read handlers to the progress display goroutine.
type readEvent struct {
	offset int64
	size   int
}

// speedSample records bytes read at a point in time for throughput calculation.
type speedSample struct {
	when  time.Time
	bytes int64
}

// speedWindow computes the throughput over the last speedWindowSize.
type speedWindow struct {
	samples []speedSample
}

// add records bytes read at the given time.
func (w *speedWindow) add(now time.Time, bytes int64) {
	w.samples = append(w.samples, speedSample{when: now, bytes: bytes})
}

// speed drops expired samples and returns the current bytes per second.
func (w *speedWindow) speed(now time.Time) float64 {
	cutoff := now.Add(-speedWindowSize)
	for len(w.samples) > 0 && w.samples[0].when.Before(cutoff) {
		w.samples = w.samples[1:]
	}
	if len(w.samples) == 0 {
		return 0
	}
	var total int64
	for _, s := range w.samples {
		total += s.bytes
	}
	elapsed := max(now.Sub(w.samples[0].when).Seconds(), minSpeedElapsed)
	return float64(total) / elapsed
}

// progress tracks transfer state and renders a live terminal display.
type progress struct {
	fileSize  int64
	fileName  string
	events    chan readEvent
	done      chan struct{}
	debugMode bool // when true, use log lines instead of \r overwriting

	mu     sync.Mutex
	client string // last active client IP
}

// setClient records the client shown in the display.
func (p *progress) setClient(ip string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.client = ip
}

// currentClient returns the client shown in the display.
func (p *progress) currentClient() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.client
}

// record reports a completed read to the display without ever blocking the reader.
func (p *progress) record(offset int64, size int) {
	select {
	case p.events <- readEvent{offset: offset, size: size}:
	default:
	}
}

// drain sums up all pending read events.
func (p *progress) drain() (bytes, reads int64) {
	for {
		select {
		case ev := <-p.events:
			bytes += int64(ev.size)
			reads++
		default:
			return bytes, reads
		}
	}
}

// run is the display goroutine. It renders a stats line to stderr.
// In normal mode: overwrites in place every 250ms.
// In debug mode: prints a log line every 2s, suppressed when idle.
func (p *progress) run() {
	interval := progressInterval
	if p.debugMode {
		interval = progressDebugInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var (
		window     speedWindow
		totalReads int64
		totalBytes int64
		started    bool
	)

	for {
		select {
		case <-p.done:
			if started && !p.debugMode {
				fmt.Fprintf(os.Stderr, "\r\033[K")
			}
			return
		case <-ticker.C:
		}

		tickBytes, tickReads := p.drain()
		totalBytes += tickBytes
		totalReads += tickReads

		if tickBytes == 0 && !started {
			continue
		}

		now := time.Now()
		if tickBytes > 0 {
			started = true
			window.add(now, tickBytes)
		}
		speed := window.speed(now)

		if p.debugMode {
			// In debug mode, skip printing when idle (speed dropped to 0).
			if speed == 0 && tickBytes == 0 {
				continue
			}
			log.Printf("[stats] %s  %s  %s reads  %s transferred",
				p.currentClient(), formatSpeed(speed), formatCount(totalReads), FormatSize(totalBytes))
		} else {
			fmt.Fprintf(os.Stderr, "\r\033[K %s  %s  %s reads  %s transferred",
				p.currentClient(), formatSpeed(speed), formatCount(totalReads), FormatSize(totalBytes))
		}
	}
}

// formatScaled renders v in the largest binary unit it reaches. Values below 1 KiB
// are whole numbers. unit is "B" or "B/s".
func formatScaled(v float64, unit string) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1f G%s", v/(1<<30), unit)
	case v >= 1<<20:
		return fmt.Sprintf("%.1f M%s", v/(1<<20), unit)
	case v >= 1<<10:
		return fmt.Sprintf("%.1f K%s", v/(1<<10), unit)
	default:
		return fmt.Sprintf("%.0f %s", v, unit)
	}
}

// FormatSize returns a human-readable size string.
func FormatSize(b int64) string {
	return formatScaled(float64(b), "B")
}

// formatSpeed returns a human-readable speed string.
func formatSpeed(bytesPerSec float64) string {
	return formatScaled(bytesPerSec, "B/s")
}

// formatCount returns an integer with comma separators (e.g. 1,204).
func formatCount(n int64) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}
