package gadgetmanager

import (
	"strings"
	"testing"
)

// TestTruncateResults_CapabilityScopedSuppressesFloodWhenIdle reproduces
// a representative workload: cuda_memtrace selected, the window is dominated by the always-on
// net flood (tailscaled net_udp_recv), and ZERO in-family GPU records exist.
// Before scoping fix the keep-set returned 64KB of unrelated net records with no
// signal; after the fix the server must report 0 in-family + N suppressed.
func TestTruncateResults_CapabilityScopedSuppressesFloodWhenIdle(t *testing.T) {
	var b strings.Builder
	flood := `{"net_op":"net_udp_recv","saddr":0,"daddr":0,"sport":41641,"proc":{"comm":"tailscaled","pid":1383}}` + "\n"
	for b.Len() < maxResultLen+8192 {
		b.WriteString(flood)
	}
	got := truncateResultsKeep(b.String(), false, "", "cuda_memtrace", "")

	if strings.Contains(got, "net_udp_recv") {
		t.Fatalf("idle-GPU scoped keep-set leaked the net flood instead of suppressing it:\n%s", got[:min(len(got), 400)])
	}
	if !strings.Contains(got, "<inFamilyRecords>0</inFamilyRecords>") {
		t.Fatalf("expected explicit 0 in-family signal, got:\n%s", got[:min(len(got), 400)])
	}
	if !strings.Contains(got, "<scopedTo>cuda_memtrace</scopedTo>") {
		t.Fatalf("expected scopedTo=cuda_memtrace, got:\n%s", got[:min(len(got), 400)])
	}
	if !strings.Contains(got, "<suppressedUnrelated>") {
		t.Fatalf("expected suppressedUnrelated count, got:\n%s", got[:min(len(got), 400)])
	}
}

// TestTruncateResults_CapabilityScopedKeepsInFamilyDropsFlood proves the mixed
// case: a few real GPU rows buried in a flood -> the scoped result keeps the
// GPU rows, drops the flood, and annotates the suppressed count.
func TestTruncateResults_CapabilityScopedKeepsInFamilyDropsFlood(t *testing.T) {
	var b strings.Builder
	flood := `{"net_op":"net_udp_recv","saddr":0,"sport":41641,"proc":{"comm":"tailscaled","pid":1383}}` + "\n"
	for b.Len() < maxResultLen+8192 {
		b.WriteString(flood)
	}
	// a genuine cuda_memtrace in-family row (carries is_runtime/op/ptr/size)
	gpu := `{"is_runtime":true,"op":"cuMemAlloc","ptr":140000000,"size":12700000000}`
	in := b.String() + gpu + "\n"
	got := truncateResultsKeep(in, false, "", "cuda_memtrace", "")

	if !strings.Contains(got, `"op":"cuMemAlloc"`) {
		t.Fatalf("scoped keep-set dropped the real in-family GPU row:\n%s", got[:min(len(got), 400)])
	}
	if strings.Contains(got, "net_udp_recv") {
		t.Fatalf("scoped keep-set leaked the net flood:\n%s", got[:min(len(got), 400)])
	}
	if !strings.Contains(got, "<scopedTo>cuda_memtrace</scopedTo>") {
		t.Fatalf("expected scopedTo annotation, got:\n%s", got[:min(len(got), 400)])
	}
	if !strings.Contains(got, "<suppressedUnrelated>") {
		t.Fatalf("expected suppressedUnrelated count, got:\n%s", got[:min(len(got), 400)])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
