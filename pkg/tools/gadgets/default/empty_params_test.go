package _default

import (
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestDefaultParamsOmitEmptyValues(t *testing.T) {
	info := &api.GadgetInfo{Params: []*api.Param{
		{Prefix: "operator.limiter.", Key: "max-entries", DefaultValue: ""},
		{Prefix: "operator.oci.", Key: "pull", DefaultValue: "never"},
	}}

	params := defaultParamsFromGadgetInfo(info)
	if _, ok := params["operator.limiter.max-entries"]; ok {
		t.Fatal("empty default must be omitted")
	}
	if got := params["operator.oci.pull"]; got != "never" {
		t.Fatalf("non-empty default changed: got %q", got)
	}
}

func TestMergeGadgetParamsIgnoresEmptyOptionalStrings(t *testing.T) {
	params := map[string]string{
		"operator.LocalManager.host": "true",
		"operator.oci.pull":          "missing",
	}
	err := mergeGadgetParams(params, map[string]interface{}{
		"operator.LocalManager.host":   "",
		"operator.limiter.max-entries": "",
		"operator.oci.wasm.capability": "net_trace",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := params["operator.LocalManager.host"]; got != "true" {
		t.Fatalf("empty override changed host default: got %q", got)
	}
	if _, ok := params["operator.limiter.max-entries"]; ok {
		t.Fatal("empty limiter override must be omitted")
	}
	if got := params["operator.oci.wasm.capability"]; got != "net_trace" {
		t.Fatalf("non-empty override missing: got %q", got)
	}
}

func TestMergeGadgetParamsRejectsNonString(t *testing.T) {
	err := mergeGadgetParams(map[string]string{}, map[string]interface{}{
		"operator.oci.wasm.pid": 123,
	})
	if err == nil {
		t.Fatal("expected non-string parameter error")
	}
}
