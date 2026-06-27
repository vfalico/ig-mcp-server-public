package gadgetmanager

import (
	"strings"
	"testing"
)

// TestGroupBy_MissingField_EmitsDiagnosticNotRaw replicates a representative workload where
// a representative workload: the client ran get_results with group_by=comm against an mm_trace window
// whose records carry NO comm/proc field. Before the fix, topGroupsSummary
// returned "" and truncateResultsKeep SILENTLY fell through to raw <results>,
// so the client saw newest records with no top-N table and believed group_by was
// ignored. After the fix the server must emit an explicit
// <groupBy requested="comm" aggregated="false"> diagnostic that (a) names the
// requested field, (b) explains it is absent, and (c) lists the fields that ARE
// groupable so the client can pick a valid dimension.
func TestGroupBy_MissingField_EmitsDiagnosticNotRaw(t *testing.T) {
	// mm_trace-style records: a page/op/order schema with NO proc/comm at all.
	recs := strings.Join([]string{
		`{"op":"alloc","order":0,"pfn":4096,"node":0}`,
		`{"op":"alloc","order":2,"pfn":8192,"node":0}`,
		`{"op":"free","order":0,"pfn":4096,"node":1}`,
	}, "\n") + "\n"

	out := truncateResultsKeep(recs, true, "comm", "", "")

	if !strings.Contains(out, `<groupBy requested="comm" aggregated="false">`) {
		t.Fatalf("expected explicit non-aggregated groupBy diagnostic, got:\n%s", out)
	}
	if !strings.Contains(out, "<groupableFields>") {
		t.Fatalf("diagnostic must list groupable fields, got:\n%s", out)
	}
	// The groupable fields must enumerate the real scalar columns present.
	for _, want := range []string{"op", "order", "pfn", "node"} {
		if !strings.Contains(out, want) {
			t.Errorf("groupableFields should advertise %q; out:\n%s", want, out)
		}
	}
	// comm must NOT be advertised as groupable (it is absent from the records).
	// Check specifically inside the <groupableFields> list, not the requested= attr.
	gfStart := strings.Index(out, "<groupableFields>")
	gfEnd := strings.Index(out, "</groupableFields>")
	if gfStart >= 0 && gfEnd > gfStart {
		list := out[gfStart:gfEnd]
		if strings.Contains(list, "comm") {
			t.Errorf("comm must not be listed groupable when absent; list=%s", list)
		}
	}
	// And the raw records must still be returned alongside the diagnostic so the
	// client keeps the data — we only ADD the explanation, never drop results.
	if !strings.Contains(out, `"op":"alloc"`) {
		t.Errorf("raw results must still accompany the diagnostic; out:\n%s", out)
	}
}

// TestGroupBy_PresentField_StillAggregates is the positive control: when the
// group_by field IS present, the real frequency table must still be produced
// (no diagnostic). Proves this fix did not regress the working path.
func TestGroupBy_PresentField_StillAggregates(t *testing.T) {
	recs := strings.Join([]string{
		`{"op":"alloc","proc":{"comm":"alpha","pid":1}}`,
		`{"op":"alloc","proc":{"comm":"alpha","pid":1}}`,
		`{"op":"free","proc":{"comm":"beta","pid":2}}`,
	}, "\n") + "\n"

	out := truncateResultsKeep(recs, true, "comm", "", "")

	if strings.Contains(out, `aggregated="false"`) {
		t.Fatalf("present field must aggregate, not emit non-aggregated diag:\n%s", out)
	}
	if !strings.Contains(out, "<topGroups") {
		t.Fatalf("expected a real topGroups aggregate table, got:\n%s", out)
	}
	// alpha appears twice, beta once -> alpha must be counted 2.
	if !strings.Contains(out, "alpha") || !strings.Contains(out, "beta") {
		t.Errorf("aggregate must include both comm values; out:\n%s", out)
	}
}

// TestScopeRecords_DatasourceIsolation replicates a representative workload where
// a representative workload: a per-comm scope (proc.comm==DIAG_case43) must isolate ONLY the
// target's records and drop the always-on fs/net flood from OTHER datasources
// (which carry a different comm, or no proc identity at all). Before the fix,
// filterRecords did a blunt substring match: "proc.comm==DIAG_case43" never
// matched the JSON "comm":"DIAG_case43" and unrelated rows leaked through.
func TestScopeRecords_DatasourceIsolation(t *testing.T) {
	// Mixed stream: 2 target rows, 1 other-comm row, 1 identity-less fs flood row.
	target1 := `{"ds":"mep_net","proc":{"comm":"DIAG_case43","pid":4242},"daddr":"10.0.0.1"}`
	target2 := `{"ds":"mep_net","proc":{"comm":"DIAG_case43","pid":4242},"daddr":"10.0.0.2"}`
	otherComm := `{"ds":"mep_net","proc":{"comm":"tailscaled","pid":900},"daddr":"8.8.8.8"}`
	noProc := `{"ds":"mep_fs","fname":"/var/log/syslog","bytes":4096}`
	stream := strings.Join([]string{target1, otherComm, noProc, target2}, "\n") + "\n"

	p, ok := parseScopePredicate("proc.comm==DIAG_case43")
	if !ok {
		t.Fatalf("parseScopePredicate failed to recognise proc.comm==DIAG_case43")
	}
	out := scopeRecords(stream, p)

	if !strings.Contains(out, `"comm":"DIAG_case43"`) {
		t.Fatalf("scoped output must retain the target rows; got:\n%s", out)
	}
	if strings.Contains(out, "tailscaled") {
		t.Errorf("other-comm row must be dropped (datasource isolation); out:\n%s", out)
	}
	if strings.Contains(out, "syslog") {
		t.Errorf("identity-less fs flood row must be dropped; out:\n%s", out)
	}
	// Exactly the 2 target rows survive.
	if got := strings.Count(strings.TrimSpace(out), "\n") + 1; got != 2 {
		t.Errorf("expected exactly 2 scoped rows, got %d; out:\n%s", got, out)
	}
}

// TestScopeRecords_BarePidAlias proves a bare identity alias (pid==N) resolves
// through the nested proc object and isolates correctly, and that a !=
// predicate excludes the named identity.
func TestScopeRecords_BarePidAlias(t *testing.T) {
	a := `{"proc":{"comm":"x","pid":111},"v":1}`
	b := `{"proc":{"comm":"y","pid":222},"v":2}`
	stream := a + "\n" + b + "\n"

	p, ok := parseScopePredicate("pid==222")
	if !ok {
		t.Fatalf("bare pid alias predicate not recognised")
	}
	out := scopeRecords(stream, p)
	if !strings.Contains(out, `"pid":222`) || strings.Contains(out, `"pid":111`) {
		t.Errorf("pid==222 must keep only pid 222; out:\n%s", out)
	}

	pne, ok := parseScopePredicate("pid!=222")
	if !ok {
		t.Fatalf("!= predicate not recognised")
	}
	outne := scopeRecords(stream, pne)
	if !strings.Contains(outne, `"pid":111`) || strings.Contains(outne, `"pid":222`) {
		t.Errorf("pid!=222 must keep only pid 111; out:\n%s", outne)
	}
}

// TestParseScopePredicate_RejectsNonIdentity proves free-form / multi-term
// filters are NOT hijacked by the scope path and fall back to substring
// filterRecords (so existing filter behaviour is preserved).
func TestParseScopePredicate_RejectsNonIdentity(t *testing.T) {
	for _, f := range []string{
		"fname==/etc/passwd", // non-identity field
		"syscall~openat",     // non-identity field
		"comm==a pid==b",     // multi-term (space)
		"daddr==1.2.3.4",     // non-identity
		"",                   // empty
		"justastring",        // no operator
	} {
		if _, ok := parseScopePredicate(f); ok {
			t.Errorf("parseScopePredicate(%q) should NOT be treated as identity scope", f)
		}
	}
	// And a genuine identity scope IS recognised.
	if _, ok := parseScopePredicate("comm==DIAG"); !ok {
		t.Errorf("comm==DIAG should be recognised as an identity scope")
	}
}
