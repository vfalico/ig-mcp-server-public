package gadgetmanager

import (
	"strings"
	"testing"
)

// review feedback / the suggestion review: prove REAL numeric SUM
// aggregation. group_by="comm:bytes" must SUM bytes per comm and rank groups by
// the SUM, so a rare-but-heavy leaker outranks a frequent-but-tiny op. This is
// the "top-N by summed bytes per pid" / "duration_ns rollup by comm/tid"
// capability the request asked for and that frequency-count group_by could not
// answer.
func TestTopGroups_SumByRanksByMetricNotFrequency(t *testing.T) {
	// leaker emits ONE huge allocation (1 GiB); noisy emits MANY tiny ones.
	// Frequency count would rank "noisy" first; sum_by must rank "leaker" first.
	var b strings.Builder
	b.WriteString(`{"comm":"leaker","bytes":1073741824}` + "\n")
	for i := 0; i < 50; i++ {
		b.WriteString(`{"comm":"noisy","bytes":8}` + "\n")
	}
	out := topGroupsSummary(b.String(), "comm:bytes", "")
	if out == "" {
		t.Fatal("expected a topGroups block, got empty")
	}
	if !strings.Contains(out, `sum_of="bytes"`) {
		t.Errorf("expected sum_of=\"bytes\" attribute, got:\n%s", out)
	}
	// leaker line must appear BEFORE noisy line (ranked by summed bytes).
	li := strings.Index(out, "comm=leaker")
	ni := strings.Index(out, "comm=noisy")
	if li < 0 || ni < 0 {
		t.Fatalf("both groups must be present, got:\n%s", out)
	}
	if li > ni {
		t.Errorf("sum_by must rank leaker (1GiB) above noisy (50x8B); got order:\n%s", out)
	}
	// leaker's summed bytes must be the exact 1073741824, rendered as a plain
	// integer (no scientific notation).
	if !strings.Contains(out, "sum_bytes=1073741824") {
		t.Errorf("expected leaker sum_bytes=1073741824 (plain int), got:\n%s", out)
	}
	// noisy summed bytes = 50*8 = 400.
	if !strings.Contains(out, "sum_bytes=400") {
		t.Errorf("expected noisy sum_bytes=400, got:\n%s", out)
	}
	// frequency count still reported alongside the sum.
	if !strings.Contains(out, "count=50") {
		t.Errorf("expected noisy count=50 alongside the sum, got:\n%s", out)
	}
}

// Plain group_by (no:metric) must keep the exact legacy frequency-count
// behaviour: no sum_of attribute, ranked by count.
func TestTopGroups_PlainGroupByUnchangedNoSum(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString(`{"comm":"a","bytes":100}` + "\n")
	}
	for i := 0; i < 2; i++ {
		b.WriteString(`{"comm":"b","bytes":999999}` + "\n")
	}
	out := topGroupsSummary(b.String(), "comm", "")
	if strings.Contains(out, "sum_of=") || strings.Contains(out, "sum_bytes=") {
		t.Errorf("plain group_by must NOT emit a sum; got:\n%s", out)
	}
	// ranked by count: a (5) before b (2) despite b's larger bytes.
	ai := strings.Index(out, "comm=a")
	bi := strings.Index(out, "comm=b")
	if ai < 0 || bi < 0 || ai > bi {
		t.Errorf("plain group_by must rank by count (a=5 before b=2); got:\n%s", out)
	}
}

// sum_by over a NESTED metric alias (duration_ns lives top-level here, but the
// dimension resolves through proc.*) exercises lookupField on both axes and the
// "duration_ns rollup by comm" wording of suggestion 235.
func TestTopGroups_SumByNestedDimension(t *testing.T) {
	var b strings.Builder
	// two processes, slow one has fewer but longer events
	b.WriteString(`{"proc":{"comm":"slow"},"duration_ns":900000}` + "\n")
	b.WriteString(`{"proc":{"comm":"slow"},"duration_ns":900000}` + "\n")
	for i := 0; i < 10; i++ {
		b.WriteString(`{"proc":{"comm":"fast"},"duration_ns":10}` + "\n")
	}
	out := topGroupsSummary(b.String(), "comm:duration_ns", "")
	if !strings.Contains(out, `sum_of="duration_ns"`) {
		t.Errorf("expected sum_of=\"duration_ns\", got:\n%s", out)
	}
	si := strings.Index(out, "comm=slow")
	fi := strings.Index(out, "comm=fast")
	if si < 0 || fi < 0 || si > fi {
		t.Errorf("slow (sum=1800000) must outrank fast (sum=100); got:\n%s", out)
	}
	if !strings.Contains(out, "sum_duration_ns=1800000") {
		t.Errorf("expected slow sum_duration_ns=1800000, got:\n%s", out)
	}
}

// A record missing the metric must still count toward frequency but contribute
// 0 to the sum (asFloat ok=false path), so distinct membership is preserved.
func TestTopGroups_SumByMissingMetricSkipsSumKeepsCount(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"comm":"x","bytes":10}` + "\n")
	b.WriteString(`{"comm":"x"}` + "\n") // no bytes field
	out := topGroupsSummary(b.String(), "comm:bytes", "")
	if !strings.Contains(out, "sum_bytes=10") {
		t.Errorf("expected sum_bytes=10 (missing-metric record skipped), got:\n%s", out)
	}
	if !strings.Contains(out, "count=2") {
		t.Errorf("expected count=2 (both records counted), got:\n%s", out)
	}
}
