package smbserver

import (
	"log"
	"sync/atomic"
	"time"
)

// debugInterval is the time between two lines of the debug display.
const debugInterval = 2 * time.Second

// debugStats tracks per-request performance metrics (lock-free via atomics). All
// methods accept a nil receiver, which is what a Server without debug output has,
// so that the read paths neither branch on debugging nor read the clock for it.
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

// now returns the current time for a later observe or elapsedNs. Without debug
// output it returns the zero time and does not read the clock.
func (d *debugStats) now() time.Time {
	if d == nil {
		return time.Time{}
	}
	return time.Now()
}

// elapsedNs returns the nanoseconds since start, which came from now.
func (d *debugStats) elapsedNs(start time.Time) int64 {
	if d == nil {
		return 0
	}
	return time.Since(start).Nanoseconds()
}

// observe records one finished read response: start and writeStart came from now,
// ioNs is the time spent reading the file and fileBytes the amount of file data.
func (d *debugStats) observe(start, writeStart time.Time, ioNs, fileBytes int64) {
	if d == nil {
		return
	}
	end := time.Now()
	total := end.Sub(start).Nanoseconds()
	d.requests.Add(1)
	d.fileBytes.Add(fileBytes)
	d.handlerNs.Add(total)
	d.ioNs.Add(ioNs)
	d.writeNs.Add(end.Sub(writeStart).Nanoseconds())
	d.recordLatency(total)
	d.recordSize(int(fileBytes))
}

// recordSize counts a read in its size bucket.
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

// recordLatency counts a handler run in its latency bucket.
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

// debugSnapshot holds the counters of debugStats at one point in time, or the
// difference between two such points.
type debugSnapshot struct {
	requests, fileBytes, handlerNs, ioNs, writeNs int64

	latency [5]int64 // <50us, <200us, <1ms, <5ms, >5ms
	size    [4]int64 // <=2K, <=8K, <=64K, >64K
}

// snapshot reads the current counters.
func (d *debugStats) snapshot() debugSnapshot {
	return debugSnapshot{
		requests:  d.requests.Load(),
		fileBytes: d.fileBytes.Load(),
		handlerNs: d.handlerNs.Load(),
		ioNs:      d.ioNs.Load(),
		writeNs:   d.writeNs.Load(),
		latency: [5]int64{
			d.latUnder50us.Load(), d.latUnder200us.Load(),
			d.latUnder1ms.Load(), d.latUnder5ms.Load(), d.latOver5ms.Load(),
		},
		size: [4]int64{
			d.sizeLE2K.Load(), d.sizeLE8K.Load(),
			d.sizeLE64K.Load(), d.sizeGT64K.Load(),
		},
	}
}

// sub returns the counters accumulated since prev.
func (s debugSnapshot) sub(prev debugSnapshot) debugSnapshot {
	diff := debugSnapshot{
		requests:  s.requests - prev.requests,
		fileBytes: s.fileBytes - prev.fileBytes,
		handlerNs: s.handlerNs - prev.handlerNs,
		ioNs:      s.ioNs - prev.ioNs,
		writeNs:   s.writeNs - prev.writeNs,
	}
	for i := range diff.latency {
		diff.latency[i] = s.latency[i] - prev.latency[i]
	}
	for i := range diff.size {
		diff.size[i] = s.size[i] - prev.size[i]
	}
	return diff
}

// runDebugDisplay prints a debug stats line to stderr every debugInterval until
// done is closed. Intervals without requests print nothing.
func (d *debugStats) runDebugDisplay(done <-chan struct{}) {
	ticker := time.NewTicker(debugInterval)
	defer ticker.Stop()

	var prev debugSnapshot
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}

		cur := d.snapshot()
		if diff := cur.sub(prev); diff.requests != 0 {
			diff.log()
		}
		prev = cur
	}
}

// log prints one line describing an interval with at least one request.
func (s debugSnapshot) log() {
	interval := debugInterval.Seconds()
	reqsPerSec := float64(s.requests) / interval
	mbPerSec := float64(s.fileBytes) / interval / float64(1<<20)
	avgHandler := time.Duration(s.handlerNs / s.requests)
	avgIO := time.Duration(s.ioNs / s.requests)
	avgWrite := time.Duration(s.writeNs / s.requests)
	avgOverhead := avgHandler - avgIO - avgWrite
	avgSize := float64(s.fileBytes) / float64(s.requests)

	// Time between requests (inverse of req/s) vs handler time = idle%.
	avgGapMs := 1000.0 / reqsPerSec
	handlerMs := float64(avgHandler.Microseconds()) / 1000.0
	idlePct := max((1.0-handlerMs/avgGapMs)*100, 0)

	// Latency distribution as percentages.
	latPct := func(i int) float64 {
		return float64(s.latency[i]) / float64(s.requests) * 100
	}

	log.Printf("[debug] %.0f req/s  %.1f MB/s  avg=%s  idle=%.0f%% | handler=%v io=%v write=%v overhead=%v | <50us:%.0f%% <200us:%.0f%% <1ms:%.0f%% <5ms:%.0f%% >5ms:%.0f%%",
		reqsPerSec, mbPerSec, FormatSize(int64(avgSize)), idlePct,
		avgHandler.Round(time.Microsecond), avgIO.Round(time.Microsecond),
		avgWrite.Round(time.Microsecond), avgOverhead.Round(time.Microsecond),
		latPct(0), latPct(1), latPct(2), latPct(3), latPct(4))
}
