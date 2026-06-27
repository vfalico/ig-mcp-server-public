package gadgetmanager

import (
	"strings"
	"testing"
)

// Part-1 (c)/(d) keep_by + group_by DISCOVERABILITY + full-set proof.
//
// Field evidence (a representative workload): a the MCP client wanting the SLOWEST individual
// syscalls shell-parsed the clipped sample and concluded "kept rows are just the
// oldest (sort doesn't apply to the stream), so rare slow events got dropped".
// The server CAN return those events (keep_by) and CAN aggregate the full set
// (group_by) -- the gap was that the positional-truncation hint never advertised
// keep_by, so the path was undiscoverable. These three guards prove (1) group_by
// counts records DROPPED from the raw window, (2) keep_by retains the heaviest
// record even when it is in the dropped-oldest zone, (3) the hint now names
// keep_by + a slow-tail example so an client can find it.

func TestTopGroups_FullSet_RareEventInDroppedTail(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5; i++ { // 5 RARE first = oldest = dropped when latest=true
		b.WriteString(`{"syscall":"RARE_SLOW","duration_ns":9000000,"proc":{"pid":99}}` + "\n")
	}
	common := `{"syscall":"common","duration_ns":1000,"proc":{"pid":1}}` + "\n"
	for b.Len() < 80*1024 { // pad > 64KB so truncation engages
		b.WriteString(common)
	}
	out := truncateResultsKeep(b.String(), true, "syscall", "trace_syscall", "")
	rs := out[strings.Index(out, "<results>"):]
	if strings.Contains(rs, "RARE_SLOW") {
		t.Fatalf("setup invalid: RARE_SLOW should be truncated from raw <results> (oldest)")
	}
	if !strings.Contains(out, "syscall=RARE_SLOW count=5") {
		t.Fatalf("FULL-SET FAIL: group_by=syscall must report RARE_SLOW count=5 over full pre-truncation set; got: %q", out[:min(len(out), 500)])
	}
}

func TestKeepBy_SlowestEventsSurviveHighVolumeStream(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"syscall":"slow","duration_ns":99000000,"proc":{"pid":7}}` + "\n") // SLOWEST, oldest
	fast := `{"syscall":"fast","duration_ns":500,"proc":{"pid":1}}` + "\n"
	for b.Len() < 80*1024 {
		b.WriteString(fast)
	}
	out := truncateResultsKeep(b.String(), true, "", "trace_syscall", "duration_ns")
	if !strings.Contains(out, "99000000") {
		t.Fatalf("keep_by=duration_ns must retain the slowest (99000000) event even though it is oldest; got: %q", out[:min(len(out), 600)])
	}
	if !strings.Contains(out, "<retention>top-by:duration_ns</retention>") {
		t.Fatalf("expected top-by retention header; got: %q", out[:min(len(out), 300)])
	}
}

func TestTruncationHint_AdvertisesKeepByForSlowTail(t *testing.T) {
	var b strings.Builder
	row := `{"syscall":"x","duration_ns":1000,"proc":{"pid":1}}` + "\n"
	for b.Len() < 90*1024 {
		b.WriteString(row)
	}
	out := truncateResultsKeep(b.String(), true, "", "trace_syscall", "")
	for _, want := range []string{"keep_by=<numeric", "duration_ns", "slow tail", "group_by=<dim>"} {
		if !strings.Contains(out, want) {
			t.Fatalf("truncation hint must mention %q so the heaviest-events path is discoverable; got: %q", want, out)
		}
	}
}
