package scanner

import "runtime"

// EffectiveWorkers returns n when it is positive, otherwise a sane default of
// max(runtime.NumCPU(), 2).
//
// Config.Workers feeds the ScanPaths semaphore directly, so a zero or negative
// value would build a zero-capacity channel: the first send blocks forever and
// the walk deadlocks instead of scanning. Clamping here — at the single place
// every entry point funnels through — keeps library callers of ScanPaths safe,
// not just the CLI flag path.
func EffectiveWorkers(n int) int {
	if n > 0 {
		return n
	}
	return max(runtime.NumCPU(), 2)
}
