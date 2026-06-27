package _default

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// TestDefaultParams_PullPolicyDefaultsToMissing proves this fix: an
// MCP gadget request must default operator.oci.pull=missing so a fixed,
// locally-built image runs from the local store instead of forcing a
// doomed pull=always registry round-trip (which surfaced as -32603
// "instantiating operator \"oci\":... pulling image (always)...: 403").
func TestDefaultParams_PullPolicyDefaultsToMissing(t *testing.T) {
	// Gadget advertises no explicit pull param.
	info := &api.GadgetInfo{Params: []*api.Param{
		{Prefix: "operator.oci.wasm.", Key: "capability", DefaultValue: ""},
	}}
	p := defaultParamsFromGadgetInfo(info)
	if got := p["operator.oci.pull"]; got != "missing" {
		t.Fatalf("expected operator.oci.pull=missing, got %q", got)
	}
}

// TestDefaultParams_PullAlwaysOverriddenToMissing proves that even when the
// daemon descriptor advertises "always" as the default, the server pins it
// to "missing" (the server image is local-only).
func TestDefaultParams_PullAlwaysOverriddenToMissing(t *testing.T) {
	info := &api.GadgetInfo{Params: []*api.Param{
		{Prefix: "operator.oci.", Key: "pull", DefaultValue: "always"},
	}}
	p := defaultParamsFromGadgetInfo(info)
	if got := p["operator.oci.pull"]; got != "missing" {
		t.Fatalf("expected pull=always to be pinned to missing, got %q", got)
	}
}

// TestDefaultParams_ExplicitPullNeverPreserved proves a caller-supplied
// explicit non-"always" policy (e.g. "never") is preserved, not clobbered.
func TestDefaultParams_ExplicitPullNeverPreserved(t *testing.T) {
	info := &api.GadgetInfo{Params: []*api.Param{
		{Prefix: "operator.oci.", Key: "pull", DefaultValue: "never"},
	}}
	p := defaultParamsFromGadgetInfo(info)
	if got := p["operator.oci.pull"]; got != "never" {
		t.Fatalf("expected explicit pull=never preserved, got %q", got)
	}
}
