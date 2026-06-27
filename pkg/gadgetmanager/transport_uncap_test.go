package gadgetmanager

import (
	"fmt"
	"strings"
	"testing"
)

// TestLimiterUncapped_DefaultSeededMinus1_DoesNotUncap is the regression guard for
// the daemon-"hang" fix. defaultParamsFromGadgetInfo seeds the gadget's REQUIRED
// limiter param with its own default "-1" on EVERY call. The OLD limiterUncapped
// read that value directly and returned true universally, disabling the 64KB
// transport cap and marshaling the full (up to ~300MB) stream -- JSON-escaping it
// exceeded the MCP client 40s timeout and surfaced as a daemon hang (the
// stdio transport wedged). The fix keys uncap off an explicit server-internal sentinel instead.
func TestLimiterUncapped_DefaultSeededMinus1_DoesNotUncap(t *testing.T) {
	// What defaultParamsFromGadgetInfo produces for every call must NOT uncap.
	seeded := map[string]string{"operator.limiter.max-entries": "-1"}
	if limiterUncapped(seeded) {
		t.Fatalf("REGRESSION: gadget-default max-entries=-1 must NOT lift the 64KB transport cap")
	}
	// A bare negative limiter VALUE (no sentinel) must also NOT uncap -- only the
	// handler-set sentinel, derived from EXPLICIT caller intent, counts.
	if limiterUncapped(map[string]string{"operator.limiter.max-entries": "-5"}) {
		t.Fatalf("REGRESSION: a bare max-entries value must not lift the cap; only the sentinel does")
	}
	// The handler-set sentinel (explicit caller intent) MUST uncap.
	if !limiterUncapped(map[string]string{TransportUncapKey: "true"}) {
		t.Fatalf("explicit transport-uncap sentinel must lift the cap")
	}
}

// TestTruncate_ExplicitUncapBoundedToFiniteCeiling proves an explicit uncap is
// bounded to maxUncapResultLen (NOT unbounded), so a pathological stream is still
// clipped and can never wedge the MCP transport (the 300MB-marshal hang).
func TestTruncate_ExplicitUncapBoundedToFiniteCeiling(t *testing.T) {
	var sb strings.Builder
	for sb.Len() < maxUncapResultLen+(1<<20) { // ~9MB > 8MB ceiling
		fmt.Fprintf(&sb, "{\"comm\":\"proc\",\"v\":%d}\n", sb.Len())
	}
	big := sb.String()
	out := truncateResultsKeep(big, true, "", "", "", true) // uncap=true
	if !strings.Contains(out, "<isTruncated>true</isTruncated>") {
		t.Fatalf("explicit uncap must STILL clip beyond the %d-byte ceiling", maxUncapResultLen)
	}
	if len(out) > maxUncapResultLen+64*1024 { // ceiling + header slack
		t.Fatalf("uncap output %d exceeds finite ceiling %d (+slack)", len(out), maxUncapResultLen)
	}
}

// TestTruncate_UncapUnderCeilingReturnsAll confirms no regression: a body UNDER the
// ceiling is returned in full under uncap (the legitimate "give me everything" case).
func TestTruncate_UncapUnderCeilingReturnsAll(t *testing.T) {
	const total = 4000
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "{\"comm\":\"proc%d\",\"v\":%d}\n", i, i)
	}
	big := sb.String() // ~120KB < 8MB
	out := truncateResultsKeep(big, true, "", "", "", true)
	if strings.Contains(out, "<isTruncated>true</isTruncated>") {
		t.Fatalf("under-ceiling uncap must NOT clip")
	}
	if got := strings.Count(out, "\"comm\":\"proc"); got != total {
		t.Fatalf("under-ceiling uncap dropped records: kept %d of %d", got, total)
	}
}
