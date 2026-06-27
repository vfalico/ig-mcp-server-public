package gadgetmanager

import (
	"fmt"
	"strings"
	"testing"
)

// TestUncap_MaxEntriesMinus1_DisablesByteCap is the DECISIVE execution proof for
// Part-1 item (d) / review feedback: when the caller passes
// operator.limiter.max-entries<0 -- uncap=true) the 64KB maxResultLen byte cap
// is lifted to the finite maxUncapResultLen ceiling so the full pre-truncation
// result set is returned for any body under that ceiling, while the DEFAULT
// (uncap=false) still clips at 64KB (no regression). NOTE: the gadget's seeded
// DEFAULT max-entries=-1 does NOT trigger uncap -- only an explicit caller value
// does (see TransportUncapKey); this unit test drives truncateResultsKeep
// directly with uncap=true/false.
//
// The contract proven here is RECORDS-DROPPED vs ALL-KEPT (the annotation
// <hint>/<isTruncated> tags are metadata layered on top of the byte body, so an
// exact total-byte assertion is the wrong contract — record survival is).
func TestUncap_MaxEntriesMinus1_DisablesByteCap(t *testing.T) {
	const total = 4000
	// Build a result body well over the 64KB cap: 4000 records ~ 45 bytes each ~ 180KB.
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "{\"comm\":\"proc%d\",\"fname\":\"/f/%d\",\"bytes\":%d}\n", i, i, i)
	}
	big := sb.String()
	if len(big) <= maxResultLen {
		t.Fatalf("test fixture too small: %d bytes <= cap %d", len(big), maxResultLen)
	}

	// DEFAULT (capped): must DROP records and mark truncated.
	capped := truncateResultsKeep(big, true, "", "", "", false)
	cappedRecs := strings.Count(capped, "\"comm\":\"proc")
	if cappedRecs >= total {
		t.Fatalf("DEFAULT path did not drop records: kept %d of %d", cappedRecs, total)
	}
	if !strings.Contains(capped, "<isTruncated>true</isTruncated>") {
		t.Fatalf("DEFAULT path should mark <isTruncated>true</isTruncated>")
	}
	// Sanity: the capped BODY (records only) stays within the byte cap.
	if cappedRecs*45 > maxResultLen+512 {
		t.Fatalf("DEFAULT path body exceeds cap: %d records ~ %d bytes", cappedRecs, cappedRecs*45)
	}

	// UNCAP (max-entries=-1): must NOT clip — ALL records returned, no truncation.
	unc := truncateResultsKeep(big, true, "", "", "", true)
	if strings.Contains(unc, "<isTruncated>true</isTruncated>") {
		t.Fatalf("UNCAP path must NOT mark truncated")
	}
	got := strings.Count(unc, "\"comm\":\"proc")
	if got != total {
		t.Fatalf("UNCAP dropped records: kept %d of %d", got, total)
	}
	t.Logf("PROOF: default kept %d/%d records (truncated); uncap kept ALL %d records",
		cappedRecs, total, got)
}

// TestUncap_ThreadsIntoKeepByRanker proves the uncap-aware effCap reaches the
// keepBy numeric ranker (the former line-1247 hard-cap, review feedback) so a
// keep_by=bytes ranked result is also returned in full when uncapped, and still
// clips by default (no regression).
func TestUncap_ThreadsIntoKeepByRanker(t *testing.T) {
	const total = 4000
	var sb strings.Builder
	for i := 0; i < total; i++ {
		fmt.Fprintf(&sb, "{\"comm\":\"p%d\",\"bytes\":%d}\n", i, i)
	}
	big := sb.String()

	// keep_by=bytes with uncap -> ranker must return all records (no byteCap clip).
	unc := truncateResultsKeep(big, true, "", "", "bytes", true)
	got := strings.Count(unc, "\"bytes\":")
	if got != total {
		t.Fatalf("UNCAP keepBy ranker dropped records: kept %d of %d", got, total)
	}

	// keep_by=bytes WITHOUT uncap -> ranker clips (drops records).
	capped := truncateResultsKeep(big, true, "", "", "bytes", false)
	cappedRecs := strings.Count(capped, "\"bytes\":")
	if cappedRecs >= total {
		t.Fatalf("DEFAULT keepBy ranker did not clip: kept %d of %d", cappedRecs, total)
	}
	t.Logf("PROOF: keepBy ranker uncap kept ALL %d; default clipped to %d records", got, cappedRecs)
}
