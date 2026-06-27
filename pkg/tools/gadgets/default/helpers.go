package _default

import (
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// ociPullParam is the OCI-handler pull-policy parameter key. ig-mcp-server
// serves a single, fixed gadget image that is built locally and (by design)
// never pushed to a public registry, so the default pull policy must prefer a
// locally-present image. See defaultParamsFromGadgetInfo.
const ociPullParam = "operator.oci.pull"

// ociPullMissing means: use the locally-present image; only pull from the
// registry if it is absent. This is the correct policy for a server that
// serves a fixed, locally-built image.
const ociPullMissing = "missing"

func defaultParamsFromGadgetInfo(info *api.GadgetInfo) map[string]string {
	params := make(map[string]string)
	for _, p := range info.Params {
		params[p.Prefix+p.Key] = p.DefaultValue
	}
	// ig-mcp-server serves a fixed, locally-built gadget image that is never
	// pushed to a registry. Without an explicit pull policy the gRPC runtime
	// defaults to "always", which forces a doomed registry round-trip for the
	// locally-only tag and surfaces to the MCP client as an opaque
	// "-32603 ... instantiating operator \"oci\": ensuring image: pulling
	// image (always) ...: 403 denied". Default to "missing" so the cached
	// image runs from the local store; a caller may still override it by
	// passing operator.oci.pull explicitly in the tool params.
	if v, ok := params[ociPullParam]; !ok || v == "" || v == "always" {
		params[ociPullParam] = ociPullMissing
	}
	return params
}

func normalizeToolName(name string) string {
	// Normalize tool name to lowercase and replace spaces with dashes
	return "gadget_" + strings.ReplaceAll(name, " ", "_")
}
