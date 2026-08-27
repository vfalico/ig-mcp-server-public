package gadgetmanager

import (
	"fmt"
	"strings"
	"testing"
)

// TestTopGroups_AggregatesOverFullPreTruncationSet proves Part-1 item (c):
// group_by frequency counts are computed over the FULL matched set BEFORE the
// 64KB keep-set cut, so DROPPED records are still counted. Without this an
// client asking "how many alpha vs beta?" on a high-volume stream would get the
// survivor-window counts (wrong) instead of the true totals.
func TestTopGroups_AggregatesOverFullPreTruncationSet(t *testing.T) {
	var b strings.Builder
	// 600 alpha at the HEAD (oldest), padded so the whole blob >> 64KB.
	pad := strings.Repeat("x", 120) // widen each record so we overflow fast
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&b, `{"op":"alpha","seq":%d,"pad":"%s"}`+"\n", i, pad)
	}
	// 600 beta at the TAIL (newest).
	for i := 0; i < 600; i++ {
		fmt.Fprintf(&b, `{"op":"beta","seq":%d,"pad":"%s"}`+"\n", i, pad)
	}
	results := b.String()
	if len(results) <= maxResultLen {
		t.Fatalf("test blob must exceed maxResultLen (%d) to force truncation; got %d", maxResultLen, len(results))
	}

	// latest=true -> keep NEWEST (beta-heavy); alpha is mostly dropped by the cut.
	// group_by="op" forces aggregation on op. capability="" so no scoping.
	got := truncateResultsKeep(results, true, "op", "", "")

	if !strings.Contains(got, "<isTruncated>true</isTruncated>") {
		t.Fatalf("expected truncation header; got head: %.200q", got)
	}
	if !strings.Contains(got, `<topGroups key="op"`) {
		t.Fatalf("expected group_by=op topGroups table; got: %.300q", got)
	}
	if !strings.Contains(got, "<aggregateComplete>true</aggregateComplete>") {
		t.Fatalf("full-set aggregate must be distinguished from the truncated raw sample: %.500q", got)
	}
	// THE item-(c) assertion: full-set counts, not survivor counts.
	if !strings.Contains(got, "op=alpha count=600") {
		t.Fatalf("item(c) VIOLATED: alpha must count 600 over the FULL pre-truncation set "+
			"(it was dropped by the keep-cut but must still be counted). got: %.500q", got)
	}
	if !strings.Contains(got, "op=beta count=600") {
		t.Fatalf("item(c): beta must count 600 over the full set. got: %.500q", got)
	}

	// Sanity: the SURVIVING <results> body must actually be smaller than the
	// full input (proving truncation really dropped records) AND must contain
	// far fewer than 600 alpha lines (proving the count above did NOT come from
	// the survivor window).
	body := got
	if i := strings.Index(body, "<results>"); i >= 0 {
		body = body[i:]
	}
	aliveAlpha := strings.Count(body, `"op":"alpha"`)
	if aliveAlpha >= 600 {
		t.Fatalf("expected most alpha records DROPPED from the kept window, but %d survived "+
			"(truncation did not bite — test is not exercising the pre-truncation path)", aliveAlpha)
	}
	t.Logf("item(c) proven: topGroups alpha=600/beta=600 over full set; only %d alpha survived the keep-cut", aliveAlpha)
}
