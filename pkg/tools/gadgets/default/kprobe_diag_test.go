package _default

import (
	"errors"
	"strings"
	"testing"
)

// realConstpropErr is a representative kprobe-attach error for a gcc .constprop clone. Before this fix
// it surfaced to the MCP client as an opaque JSON-RPC -32603 internal error.
const realConstpropErr = `starting gadget mcp_ebpf_proxy:local: running gadget: rpc error: code = Unknown desc = starting operators: starting operator "oci": starting operator "ebpf": attaching eBPF program "mep_kretprobe": creating tracefs event (arch-specific fallback for "__alloc_pages_slowpath.constprop.0"): creating probe entry on tracefs: token __x64___alloc_pages_slowpath.constprop.0: writing 'r:ebpf_5275e67751e7b58c/_x64_alloc_pages_slowpath_constprop_0 __x64___alloc_pages_slowpath.constprop.0': write /sys/kernel/tracing/kprobe_events: invalid argument`

// TestIsKprobeAttachFailure_DetectsRealWireError proves the classifier matches
// the exact production -32603 payload that motivated this fix.
func TestIsKprobeAttachFailure_DetectsRealWireError(t *testing.T) {
	if !isKprobeAttachFailure(errors.New(realConstpropErr)) {
		t.Fatal("classifier failed to match the real .constprop kprobe-attach -32603 error")
	}
}

// TestIsKprobeAttachFailure_IgnoresUnrelated proves we do NOT swallow unrelated
// errors (they must still propagate as real faults).
func TestIsKprobeAttachFailure_IgnoresUnrelated(t *testing.T) {
	for _, e := range []error{
		nil,
		errors.New("pulling image (always): 403 Forbidden"),
		errors.New("context deadline exceeded"),
		errors.New("output too large: 70000 bytes"),
	} {
		if isKprobeAttachFailure(e) {
			t.Fatalf("classifier wrongly matched unrelated error: %v", e)
		}
	}
}

// TestKprobeAttachDiagnostic_NamesSymbolAndForbidsRetry proves the structured
// hint (a) names the offending symbol, (b) identifies the constprop clone and
// suggests the canonical base symbol, and (c) explicitly tells the agent not to
// retry the same symbol — the behavior that prevents an agent from retrying
// the identical un-attachable symbol.
func TestKprobeAttachDiagnostic_NamesSymbolAndForbidsRetry(t *testing.T) {
	msg := kprobeAttachDiagnostic("mcp_ebpf_proxy:local", errors.New(realConstpropErr))
	for _, want := range []string{
		"__alloc_pages_slowpath.constprop.0", // names the bad symbol
		"compiler clone",                     // explains why
		"available_filter_functions",         // points at the kernel source of truth
		"__alloc_pages_slowpath",             // suggests canonical base (suffix stripped)
		"DO NOT retry the same symbol",       // forbids the wasteful retry
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("diagnostic missing %q.\nGot:\n%s", want, msg)
		}
	}
	// The base suggestion must be the clone-stripped form, distinct from the clone.
	if !strings.Contains(msg, `Try the canonical (non-clone) symbol "__alloc_pages_slowpath"`) {
		t.Fatalf("diagnostic did not suggest the canonical base symbol.\nGot:\n%s", msg)
	}
}

// TestCloneSuffixRe_Variants proves the clone detector covers the common GCC
// optimization suffixes, not just constprop.
func TestCloneSuffixRe_Variants(t *testing.T) {
	clones := []string{"foo.constprop.0", "bar.isra.0", "baz.part.5", "qux.cold"}
	for _, c := range clones {
		if !cloneSuffixRe.MatchString(c) {
			t.Fatalf("expected %q to be detected as a clone suffix", c)
		}
	}
	for _, ok := range []string{"__alloc_pages_slowpath", "vfs_read", "tcp_sendmsg"} {
		if cloneSuffixRe.MatchString(ok) {
			t.Fatalf("plain symbol %q wrongly flagged as a clone", ok)
		}
	}
}
