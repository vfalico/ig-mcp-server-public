package gadgetmanager

import (
	"regexp"
	"strings"
	"testing"
)

// TestInFamily_PriorityRetention_FloodNeverEvicts proves Part-1 item (a): when a
// capability is selected, the keep-set fills with that capability's in-family
// records FIRST and the always-on fs/net flood can never evict them — even when
// the COMBINED stream vastly exceeds the 64KB byte cap and the flood records are
// positionally NEWER (so a naive newest-slice cut would keep flood and drop the
// in-family records). The scoping partition must run BEFORE the positional cut.
func TestInFamily_PriorityRetention_FloodNeverEvicts(t *testing.T) {
	var b strings.Builder
	// Enough genuine in-family fs_trace records FIRST (older) that the in-family
	// slice ALONE exceeds the 64KB cap — this forces the ACTIVE truncation branch
	// (the one that emits <keptRecords>/<inFamilyRecords>) rather than the
	// fits-under-cap branch. Each record ~300 bytes -> ~300 records > 64KB.
	const inFamN = 400
	for i := 0; i < inFamN; i++ {
		b.WriteString(`{"fs_op":"fs_open","fname":"/var/lib/app/data`)
		b.WriteString(strings.Repeat("x", 200))
		b.WriteString(`","proc":{"comm":"app","pid":1234,"tid":1234},"retval":0}` + "\n")
	}
	// A HUGE unrelated flood AFTER them (newer) — tailscaled/net_udp records with
	// NO fs_trace signature. Big enough that in-family + flood >> 64KB cap, and the
	// flood alone already exceeds the cap. A newest-slice cut would keep ONLY flood.
	floodRec := `{"net_op":"net_udp_recv","comm":"tailscaled","sport":41641,"dport":3478,"payload":"` + strings.Repeat("Z", 200) + `"}` + "\n"
	floodN := (70 * 1024) / len(floodRec) // ~ enough to blow past 64KB on its own
	for i := 0; i < floodN; i++ {
		b.WriteString(floodRec)
	}
	stream := b.String()
	if len(stream) <= 64*1024 {
		t.Fatalf("test setup: stream %d bytes must exceed 64KB cap to exercise truncation", len(stream))
	}

	// latest=true would, WITHOUT scoping, keep the newest (=flood) records and
	// evict every in-family record. The scoping partition must defeat that.
	out := truncateResultsKeep(stream, true /*latest*/, "" /*groupBy*/, "fs_trace", "" /*keepBy*/)

	// (1) zero flood records survive in the emitted <results> body.
	resBody := out
	if i := strings.Index(out, "<results>"); i >= 0 {
		resBody = out[i:]
	}
	if strings.Contains(resBody, "net_udp_recv") || strings.Contains(resBody, "tailscaled") {
		t.Fatalf("FLOOD SURVIVED: a net_udp_recv/tailscaled record leaked into the kept set — in-family priority FAILED.\nout head:\n%s", out[:min(800, len(out))])
	}
	// (2) every kept record carries the fs_trace signature. Records are
	// newline-delimited JSONL; count lines that are JSON objects (records carry
	// a nested "proc":{...} object so a brace-class regex cannot delimit them).
	inner := resBody
	if i := strings.Index(inner, "<results>"); i >= 0 {
		inner = inner[i+len("<results>"):]
	}
	if i := strings.Index(inner, "</results>"); i >= 0 {
		inner = inner[:i]
	}
	var allObjs, keptObjs int
	for _, ln := range strings.Split(strings.TrimSpace(inner), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] != '{' {
			continue
		}
		allObjs++
		if strings.Contains(ln, `"fs_op"`) && strings.Contains(ln, `"fname"`) {
			keptObjs++
		}
	}
	if keptObjs == 0 {
		t.Fatalf("NO in-family records kept — survival FAILED.\nout:\n%s", out[:min(800, len(out))])
	}
	if keptObjs != allObjs {
		t.Fatalf("kept set not 100%% in-family: %d/%d carry fs_op+fname", keptObjs, allObjs)
	}
	// (3) the new self-verifying telemetry: inFamilyRecords == keptRecords.
	inFam := tagInt(t, out, "inFamilyRecords")
	kept := tagInt(t, out, "keptRecords")
	if inFam != kept {
		t.Fatalf("inFamilyRecords(%d) != keptRecords(%d): kept set is NOT entirely in-family", inFam, kept)
	}
	// The in-family slice itself overflows 64KB so it is positionally clipped:
	// inFamilyRecords (== keptRecords) is a subset of inFamN, but CRUCIALLY every
	// kept record is in-family and the kept count matches the in-family count
	// (proving flood contributed ZERO records to the keep-set).
	if inFam <= 0 || inFam > inFamN {
		t.Fatalf("inFamilyRecords=%d out of range (0,%d]", inFam, inFamN)
	}
	// (4) suppressedUnrelated must account for the flood.
	supp := tagInt(t, out, "suppressedUnrelated")
	if supp != floodN {
		t.Fatalf("suppressedUnrelated=%d, expected flood count %d", supp, floodN)
	}
	t.Logf("PROVEN item(a): %d in-family kept, 0 flood survived, %d flood suppressed (stream was %d bytes, cap 64KB, newest-slice mode)", inFam, supp, len(stream))
}

var tagRe = map[string]*regexp.Regexp{}

func tagInt(t *testing.T, s, tag string) int {
	re, ok := tagRe[tag]
	if !ok {
		re = regexp.MustCompile(`<` + tag + `>(\d+)</` + tag + `>`)
		tagRe[tag] = re
	}
	m := re.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("tag <%s> not found in output:\n%s", tag, s[:min(900, len(s))])
	}
	n := 0
	for _, c := range m[1] {
		n = n*10 + int(c-'0')
	}
	return n
}
