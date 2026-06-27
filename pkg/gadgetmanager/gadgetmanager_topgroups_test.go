package gadgetmanager

import (
	"strings"
	"testing"
)

// TestTopGroups_NestedProcGroupBy proves the nested per-process group_by behavior:
// lock_trace nests process identity under "proc", so group_by=pid / group_by=tid
// must resolve THROUGH the nested object and aggregate over the FULL set, instead
// of silently matching nothing (which forced the client to hand-parse the clipped
// "oldest 95" sample of a 1,635,196-record stream). Records mirror the real
// a representative workload lock_trace schema captured on the wire (proc.{pid,tid,comm}, addr, lock_op).
func TestTopGroups_NestedProcGroupBy(t *testing.T) {
	// 5 records: pid 100 (3x, tids 100/101/102) and pid 200 (2x, tids 200/201)
	recs := strings.Join([]string{
		`{"addr":101643636445344,"lock_op":"lock_futex_wait","duration_ns":2254,"proc":{"comm":"DIAG","pid":100,"tid":100}}`,
		`{"addr":101643636445344,"lock_op":"lock_futex_wait","duration_ns":3000,"proc":{"comm":"DIAG","pid":100,"tid":101}}`,
		`{"addr":109779528,"lock_op":"lock_futex_wait","duration_ns":900,"proc":{"comm":"DIAG","pid":100,"tid":102}}`,
		`{"addr":109779528,"lock_op":"lock_futex_wait","duration_ns":700,"proc":{"comm":"OTHER","pid":200,"tid":200}}`,
		`{"addr":109779528,"lock_op":"lock_futex_wait","duration_ns":650,"proc":{"comm":"OTHER","pid":200,"tid":201}}`,
	}, "\n")

	// group_by=pid: full-set aggregate keyed on nested proc.pid
	gotPid := topGroupsSummary(recs, "pid", "lock_trace")
	if !strings.Contains(gotPid, `key="pid"`) {
		t.Fatalf("group_by=pid did not key on nested proc.pid; got:\n%s", gotPid)
	}
	if !strings.Contains(gotPid, "pid=100 count=3") {
		t.Errorf("expected pid=100 count=3 over full set; got:\n%s", gotPid)
	}
	if !strings.Contains(gotPid, "pid=200 count=2") {
		t.Errorf("expected pid=200 count=2 over full set; got:\n%s", gotPid)
	}

	// group_by=tid: distinct waiter threads (the exact metric a representative workload's client wanted)
	gotTid := topGroupsSummary(recs, "tid", "lock_trace")
	if !strings.Contains(gotTid, `key="tid"`) || !strings.Contains(gotTid, `distinct="5"`) {
		t.Errorf("expected 5 distinct waiter tids over full set; got:\n%s", gotTid)
	}

	// group_by=comm: nested process name
	gotComm := topGroupsSummary(recs, "comm", "lock_trace")
	if !strings.Contains(gotComm, "comm=DIAG count=3") || !strings.Contains(gotComm, "comm=OTHER count=2") {
		t.Errorf("expected comm aggregate DIAG=3 OTHER=2; got:\n%s", gotComm)
	}

	// default (no group_by) still keys on the flat natural key addr — backward compat
	gotDef := topGroupsSummary(recs, "", "lock_trace")
	if !strings.Contains(gotDef, `key="addr"`) {
		t.Errorf("default lock_trace summary must still key on addr; got:\n%s", gotDef)
	}
}

// TestLookupField_Resolution unit-tests the resolver across flat / dotted / alias.
func TestLookupField_Resolution(t *testing.T) {
	m := map[string]interface{}{
		"addr": float64(42),
		"proc": map[string]interface{}{
			"pid": float64(100), "tid": float64(101), "comm": "x",
			"parent": map[string]interface{}{"pid": float64(7)},
			"creds":  map[string]interface{}{"uid": float64(1000), "user": "alice"},
		},
	}
	cases := []struct {
		key  string
		want interface{}
		ok   bool
	}{
		{"addr", float64(42), true},           // flat
		{"pid", float64(100), true},           // alias -> proc.pid
		{"tid", float64(101), true},           // alias -> proc.tid
		{"comm", "x", true},                   // alias -> proc.comm
		{"proc.pid", float64(100), true},      // dotted
		{"proc.parent.pid", float64(7), true}, // deep dotted
		{"ppid", float64(7), true},            // alias -> proc.parent.pid
		{"uid", float64(1000), true},          // alias -> proc.creds.uid
		{"user", "alice", true},               // alias -> proc.creds.user
		{"nope", nil, false},                  // absent
	}
	for _, c := range cases {
		got, ok := lookupField(m, c.key)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("lookupField(%q)=(%v,%v) want (%v,%v)", c.key, got, ok, c.want, c.ok)
		}
	}
}
