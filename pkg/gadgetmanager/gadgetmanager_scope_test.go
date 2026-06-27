// Copyright 2026 The Inspektor Gadget authors
// Licensed under the Apache License, Version 2.0
//
// scoping fix regression tests for capability-scoped result assembly:
// - group-by table is emitted for sub-cap (untruncated) output when the
// caller asks (group_by=) or a capability with a natural key is selected;
// - the unscoped/ungrouped small-result path stays byte-for-byte legacy;
// - partitionByCapability splits in-family vs always-on fs/net noise;
// - the truncation keep-set retains in-family records over the flood.
package gadgetmanager

import (
	"strings"
	"testing"
)

func TestTruncateResults_SmallOutputLegacyUnchanged(t *testing.T) {
	in := `{"fs_op":"open","fname":"/a"}` + "\n" + `{"fs_op":"close","fname":"/a"}`
	// no group_by, no capability with a natural key -> legacy <results> only.
	got := truncateResultsKeep(in, false, "", "", "")
	want := "\n<results>" + in + "</results>\n"
	if got != want {
		t.Fatalf("legacy small-output path changed:\n got=%q\nwant=%q", got, want)
	}
	if strings.Contains(got, "<topGroups") {
		t.Fatalf("topGroups must NOT appear for ungrouped/unscoped small output: %q", got)
	}
}

func TestTruncateResults_SmallOutputGroupByEmitsTable(t *testing.T) {
	in := strings.Join([]string{
		`{"syscall":"openat","pid":1}`,
		`{"syscall":"openat","pid":2}`,
		`{"syscall":"close","pid":1}`,
	}, "\n")
	got := truncateResultsKeep(in, false, "syscall", "", "")
	if !strings.Contains(got, `<topGroups key="syscall"`) {
		t.Fatalf("group_by=syscall should emit a topGroups table for small output: %q", got)
	}
	if !strings.Contains(got, "syscall=openat count=2") {
		t.Fatalf("group_by table should rank openat=2: %q", got)
	}
	if !strings.Contains(got, "<results>"+in+"</results>") {
		t.Fatalf("raw results must still be included: %q", got)
	}
}

func TestTruncateResults_SmallOutputCapabilityNaturalKey(t *testing.T) {
	// lock_trace's natural key is addr; selecting the capability (no group_by)
	// should still produce a ranked table on small output.
	in := strings.Join([]string{
		`{"addr":"0xff01","lock_op":"acquire"}`,
		`{"addr":"0xff01","lock_op":"release"}`,
		`{"addr":"0xbeef","lock_op":"acquire"}`,
	}, "\n")
	got := truncateResultsKeep(in, false, "", "lock_trace", "")
	if !strings.Contains(got, `<topGroups key="addr"`) {
		t.Fatalf("lock_trace capability should key topGroups on addr for small output: %q", got)
	}
	if !strings.Contains(got, "addr=0xff01 count=2") {
		t.Fatalf("addr 0xff01 should rank 2: %q", got)
	}
}

func TestPartitionByCapability(t *testing.T) {
	in := strings.Join([]string{
		`{"gpu_pid":4189390,"used_gpu_mem":12700000000}`, // in-family (cuda_memsnapshot)
		`{"fs_op":"open","fname":"/etc/hosts"}`,          // noise
		`{"smu_pid":1,"recent_sm_util":0}`,               // not cuda_memsnapshot family
	}, "\n")
	inFam, other := partitionByCapability(in, "cuda_memsnapshot")
	if !strings.Contains(inFam, "gpu_pid") {
		t.Fatalf("gpu_pid record should be in-family: inFam=%q", inFam)
	}
	if strings.Contains(inFam, "fs_op") {
		t.Fatalf("fs noise leaked into in-family: %q", inFam)
	}
	if !strings.Contains(other, "fs_op") {
		t.Fatalf("fs noise should be in 'other': %q", other)
	}
}

func TestTruncateResults_KeepSetRetainsInFamily(t *testing.T) {
	// Build > maxResultLen of fs noise, then a single rare GPU row at the end.
	var b strings.Builder
	noise := `{"fs_op":"open","fname":"/x/y/z/some/longish/path/to/inflate"}` + "\n"
	for b.Len() < maxResultLen+8192 {
		b.WriteString(noise)
	}
	gpu := `{"gpu_pid":4189390,"used_gpu_mem":12700000000}`
	in := b.String() + gpu
	// newest-mode (latest=true) keeps the tail; with capability scoping the GPU
	// row must survive even though it is a single needle in a fs haystack.
	got := truncateResultsKeep(in, true, "", "cuda_memsnapshot", "")
	if !strings.Contains(got, "gpu_pid") {
		t.Fatalf("capability-scoped keep-set dropped the in-family GPU row")
	}
	if !strings.Contains(got, "<isTruncated>true</isTruncated>") {
		t.Fatalf("expected truncation header for oversize input")
	}
}

func TestKeepTopNByNumeric_RanksDesc(t *testing.T) {
	in := strings.Join([]string{
		`{"gpu_pid":1,"used_gpu_mem":100}`,
		`{"gpu_pid":2,"used_gpu_mem":9000}`,
		`{"gpu_pid":3,"used_gpu_mem":50}`,
	}, "\n")
	got, ok := keepTopNByNumeric(in, "used_gpu_mem", maxResultLen)
	if !ok {
		t.Fatalf("expected ok=true when field present")
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"used_gpu_mem":9000`) {
		t.Fatalf("heaviest record must be first: %q", got)
	}
	if !strings.Contains(lines[2], `"used_gpu_mem":50`) {
		t.Fatalf("smallest record must be last: %q", got)
	}
}

func TestKeepTopNByNumeric_MissingFieldFallsBack(t *testing.T) {
	in := `{"fs_op":"open","fname":"/a"}` + "\n" + `{"fs_op":"close","fname":"/a"}`
	_, ok := keepTopNByNumeric(in, "used_gpu_mem", maxResultLen)
	if ok {
		t.Fatalf("ok must be false when no record carries the field (caller falls back to positional)")
	}
}

func TestKeepTopNByNumeric_RecordsWithoutFieldSortLast(t *testing.T) {
	in := strings.Join([]string{
		`{"comm":"a","duration_ns":5}`,
		`{"comm":"b"}`, // no duration_ns
		`{"comm":"c","duration_ns":999}`,
	}, "\n")
	got, ok := keepTopNByNumeric(in, "duration_ns", maxResultLen)
	if !ok {
		t.Fatalf("expected ok=true")
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if !strings.Contains(lines[0], `"duration_ns":999`) {
		t.Fatalf("largest duration first: %q", got)
	}
	if !strings.Contains(lines[2], `"comm":"b"`) {
		t.Fatalf("field-less record must sort last: %q", got)
	}
}

func TestTruncateResultsKeep_NumericRetentionSurvivesFlood(t *testing.T) {
	// Build > maxResultLen of small-VRAM noise, then ONE huge-VRAM row in the
	// MIDDLE (not newest). Positional newest-mode would evict it; keep_by must
	// retain it.
	var b strings.Builder
	for i := 0; b.Len() < maxResultLen+8192; i++ {
		b.WriteString(`{"gpu_pid":99,"used_gpu_mem":1}` + "\n")
		if b.Len() > (maxResultLen/2) && b.Len() < (maxResultLen/2)+40 {
			b.WriteString(`{"gpu_pid":7,"used_gpu_mem":80000000000}` + "\n")
		}
	}
	got := truncateResultsKeep(b.String(), true, "", "", "used_gpu_mem")
	if !strings.Contains(got, `"used_gpu_mem":80000000000`) {
		t.Fatalf("keep_by=used_gpu_mem must retain the heavy row buried mid-stream")
	}
	if !strings.Contains(got, "<retention>top-by:used_gpu_mem</retention>") {
		t.Fatalf("expected retention header: head=%q", got[:200])
	}
}

func TestTopGroups_CapabilityScopedNotHijackedByFnameFlood(t *testing.T) {
	// cuda_memsnapshot selected; window has ONE real cuda row plus a
	// flood of always-on fs records. The summary MUST key on the cuda natural
	// field (gpu_pid), NOT the fs fname flood.
	in := strings.Join([]string{
		`{"gpu_pid":4189390,"used_gpu_mem":12700000000,"memsnap_op":"proc"}`,
		`{"fs_op":"open","fname":"/etc/hosts"}`,
		`{"fs_op":"open","fname":"/etc/hosts"}`,
		`{"fs_op":"read","fname":"/var/log/syslog"}`,
	}, "\n")
	got := truncateResultsKeep(in, false, "", "cuda_memsnapshot", "")
	if !strings.Contains(got, `<topGroups key="gpu_pid"`) {
		t.Fatalf("cuda_memsnapshot summary must key on gpu_pid, not the fname flood: %q", got)
	}
	if strings.Contains(got, `key="fname"`) {
		t.Fatalf("fname flood must NOT hijack the capability summary: %q", got)
	}
}

func TestTopGroups_CapabilitySelectedButNoInFamilyRowsOmitsBlock(t *testing.T) {
	// cuda_memsnapshot selected but the window captured ZERO cuda rows
	// (only the always-on flood). The summary MUST be omitted rather than
	// mislabelling the flood under the cuda banner.
	in := strings.Join([]string{
		`{"fs_op":"open","fname":"/etc/hosts"}`,
		`{"fs_op":"read","fname":"/var/log/syslog"}`,
	}, "\n")
	got := truncateResultsKeep(in, false, "", "cuda_memsnapshot", "")
	if strings.Contains(got, "<topGroups") {
		t.Fatalf("no in-family cuda rows -> topGroups must be omitted, got: %q", got)
	}
}
