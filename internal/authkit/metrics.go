package authkit

import "sync"

// MetricsRecorder increments counters for auth events.
type MetricsRecorder interface {
	Increment(event string)
}

// CounterMetrics implements MetricsRecorder with in-memory counts.
type CounterMetrics struct {
	mutex  sync.Mutex
	counts map[string]int64
}

// NewCounterMetrics constructs an in-memory metrics recorder.
func NewCounterMetrics() *CounterMetrics {
	return &CounterMetrics{counts: make(map[string]int64)}
}

// Increment increases the counter for the given event.
func (recorder *CounterMetrics) Increment(event string) {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	recorder.counts[event]++
}

// Count returns the current value for the given event.
func (recorder *CounterMetrics) Count(event string) int64 {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return recorder.counts[event]
}

// Snapshot returns a copy of all recorded counters.
func (recorder *CounterMetrics) Snapshot() map[string]int64 {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	clone := make(map[string]int64, len(recorder.counts))
	for key, value := range recorder.counts {
		clone[key] = value
	}
	return clone
}
