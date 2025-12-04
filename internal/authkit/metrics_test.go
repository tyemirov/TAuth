package authkit

import "testing"

func TestCounterMetricsSnapshot(t *testing.T) {
	metrics := NewCounterMetrics()
	metrics.Increment(metricAuthLoginSuccess)
	metrics.Increment(metricAuthLoginSuccess)
	metrics.Increment(metricAuthLogoutSuccess)

	snapshot := metrics.Snapshot()
	if snapshot[metricAuthLoginSuccess] != 2 {
		t.Fatalf("expected login count 2, got %d", snapshot[metricAuthLoginSuccess])
	}
	if snapshot[metricAuthLogoutSuccess] != 1 {
		t.Fatalf("expected logout count 1, got %d", snapshot[metricAuthLogoutSuccess])
	}
	if _, ok := snapshot[metricAuthRefreshSuccess]; ok {
		t.Fatalf("did not expect refresh metric in snapshot")
	}
}
