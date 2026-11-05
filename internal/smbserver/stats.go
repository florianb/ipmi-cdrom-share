package smbserver

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// debugStats tracks per-request performance metrics (lock-free via atomics).
type debugStats struct {
	requests  atomic.Int64
	fileBytes atomic.Int64
	handlerNs atomic.Int64 // total handler time (parse to write-complete)
	ioNs      atomic.Int64 // time in ReadAt
	writeNs   atomic.Int64 // time in conn.Write

	// Handler latency histogram.
	latUnder50us  atomic.Int64
	latUnder200us atomic.Int64
	latUnder1ms   atomic.Int64
	latUnder5ms   atomic.Int64
	latOver5ms    atomic.Int64

	// Read size buckets.
	sizeLE2K  atomic.Int64
	sizeLE8K  atomic.Int64
	sizeLE64K atomic.Int64
	sizeGT64K atomic.Int64
}

func (d *debugStats) recordSize(n int) {
	switch {
	case n <= 2048:
		d.sizeLE2K.Add(1)
	case n <= 8192:
		d.sizeLE8K.Add(1)
	case n <= 65536:
		d.sizeLE64K.Add(1)
	default:
		d.sizeGT64K.Add(1)
	}
}

func (d *debugStats) recordLatency(ns int64) {
	switch {
	case ns < 50_000:
		d.latUnder50us.Add(1)
	case ns < 200_000:
		d.latUnder200us.Add(1)
	case ns < 1_000_000:
		d.latUnder1ms.Add(1)
	case ns < 5_000_000:
		d.latUnder5ms.Add(1)
	default:
		d.latOver5ms.Add(1)
	}
}

// runDebugDisplay prints a debug stats line to stderr every 2 seconds until done
// is closed.
func (d *debugStats) runDebugDisplay(done <-chan struct{}) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	var prevReqs, prevBytes, prevHandlerNs, prevIONs, prevWriteNs int64
	var prevLat [5]int64 // <50us, <200us, <1ms, <5ms, >5ms
	var prevSize [4]int64

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}

		reqs := d.requests.Load()
		bytes := d.fileBytes.Load()
		handlerNs := d.handlerNs.Load()
		ioNs := d.ioNs.Load()
		writeNs := d.writeNs.Load()
		lat := [5]int64{
			d.latUnder50us.Load(), d.latUnder200us.Load(),
			d.latUnder1ms.Load(), d.latUnder5ms.Load(), d.latOver5ms.Load(),
		}
		size := [4]int64{
			d.sizeLE2K.Load(), d.sizeLE8K.Load(),
			d.sizeLE64K.Load(), d.sizeGT64K.Load(),
		}

		dReqs := reqs - prevReqs
		dBytes := bytes - prevBytes
		dHandlerNs := handlerNs - prevHandlerNs
		dIONs := ioNs - prevIONs
		dWriteNs := writeNs - prevWriteNs
		var dLat [5]int64
		for i := range dLat {
			dLat[i] = lat[i] - prevLat[i]
		}
		var dSize [4]int64
		for i := range dSize {
			dSize[i] = size[i] - prevSize[i]
		}

		prevReqs = reqs
		prevBytes = bytes
		prevHandlerNs = handlerNs
		prevIONs = ioNs
		prevWriteNs = writeNs
		prevLat = lat
		prevSize = size

		if dReqs == 0 {
			continue
		}

		reqsPerSec := float64(dReqs) / 2.0
		mbPerSec := float64(dBytes) / 2.0 / float64(1<<20)
		avgHandler := time.Duration(dHandlerNs / dReqs)
		avgIO := time.Duration(dIONs / dReqs)
		avgWrite := time.Duration(dWriteNs / dReqs)
		avgOverhead := avgHandler - avgIO - avgWrite
		avgSize := float64(dBytes) / float64(dReqs)

		// Time between requests (inverse of req/s) vs handler time = idle%.
		avgGapMs := 1000.0 / reqsPerSec
		handlerMs := float64(avgHandler.Microseconds()) / 1000.0
		idlePct := (1.0 - handlerMs/avgGapMs) * 100
		if idlePct < 0 {
			idlePct = 0
		}

		// Latency distribution as percentages.
		latPct := func(i int) float64 {
			return float64(dLat[i]) / float64(dReqs) * 100
		}

		log.Printf("[debug] %.0f req/s  %.1f MB/s  avg=%s  idle=%.0f%% | handler=%v io=%v write=%v overhead=%v | <50us:%.0f%% <200us:%.0f%% <1ms:%.0f%% <5ms:%.0f%% >5ms:%.0f%%",
			reqsPerSec, mbPerSec, FormatSize(int64(avgSize)), idlePct,
			avgHandler.Round(time.Microsecond), avgIO.Round(time.Microsecond),
			avgWrite.Round(time.Microsecond), avgOverhead.Round(time.Microsecond),
			latPct(0), latPct(1), latPct(2), latPct(3), latPct(4))
	}
}

// readEvent is sent from handleRead to the progress display goroutine.
type readEvent struct {
	offset int64
	size   int
}

// speedSample records bytes read at a point in time for throughput calculation.
type speedSample struct {
	when  time.Time
	bytes int64
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

// FormatSize returns a human-readable size string.
func FormatSize(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
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

// formatSpeed returns a human-readable speed string.
func formatSpeed(bytesPerSec float64) string {
	switch {
	case bytesPerSec >= float64(1<<30):
		return fmt.Sprintf("%.1f GB/s", bytesPerSec/float64(1<<30))
	case bytesPerSec >= float64(1<<20):
		return fmt.Sprintf("%.1f MB/s", bytesPerSec/float64(1<<20))
	case bytesPerSec >= float64(1<<10):
		return fmt.Sprintf("%.1f KB/s", bytesPerSec/float64(1<<10))
	default:
		return fmt.Sprintf("%.0f B/s", bytesPerSec)
	}
}

// record reports a completed read to the display without ever blocking the reader.
func (p *progress) record(offset int64, size int) {
	select {
	case p.events <- readEvent{offset: offset, size: size}:
	default:
	}
}

// run is the display goroutine. It renders a stats line to stderr.
// In normal mode: overwrites in place every 250ms.
// In debug mode: prints a log line every 2s, suppressed when idle.
func (p *progress) run() {
	interval := 250 * time.Millisecond
	if p.debugMode {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var (
		speedBuf   []speedSample
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

		// Drain all pending events.
		var tickBytes int64
		var tickReads int64
		for {
			select {
			case ev := <-p.events:
				tickBytes += int64(ev.size)
				tickReads++
			default:
				goto drained
			}
		}
	drained:

		totalBytes += tickBytes
		totalReads += tickReads

		if tickBytes == 0 && !started {
			continue
		}

		now := time.Now()
		if tickBytes > 0 {
			started = true
			speedBuf = append(speedBuf, speedSample{when: now, bytes: tickBytes})
		}

		// Expire old speed samples (keep 2 seconds).
		cutoff := now.Add(-2 * time.Second)
		for len(speedBuf) > 0 && speedBuf[0].when.Before(cutoff) {
			speedBuf = speedBuf[1:]
		}

		// Calculate speed.
		var totalSpeedBytes int64
		for _, s := range speedBuf {
			totalSpeedBytes += s.bytes
		}
		var speed float64
		if len(speedBuf) > 0 {
			elapsed := now.Sub(speedBuf[0].when).Seconds()
			if elapsed < 0.25 {
				elapsed = 0.25
			}
			speed = float64(totalSpeedBytes) / elapsed
		}

		p.mu.Lock()
		client := p.client
		p.mu.Unlock()

		if p.debugMode {
			// In debug mode, skip printing when idle (speed dropped to 0).
			if speed == 0 && tickBytes == 0 {
				continue
			}
			log.Printf("[stats] %s  %s  %s reads  %s transferred",
				client, formatSpeed(speed), formatCount(totalReads), FormatSize(totalBytes))
		} else {
			fmt.Fprintf(os.Stderr, "\r\033[K %s  %s  %s reads  %s transferred",
				client, formatSpeed(speed), formatCount(totalReads), FormatSize(totalBytes))
		}
	}
}
