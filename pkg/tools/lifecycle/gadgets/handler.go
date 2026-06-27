package gadgets

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/inspektor-gadget/ig-mcp-server/pkg/gadgetmanager"
)

var log = slog.Default().With("component", "lifecycle_gadgets_tool")

func lifecycleHandler(mgr gadgetmanager.GadgetManager) server.ToolHandlerFunc {
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		action := request.GetString("action", "")
		if action == "" {
			return mcp.NewToolResultText("No action specified, must be one of: " + strings.Join(gadgetActions, ", ")), nil
		}
		if !slices.Contains(gadgetActions, action) {
			return mcp.NewToolResultError("Invalid action specified, must be one of: " + strings.Join(gadgetActions, ", ")), nil
		}

		gadgetID := request.GetString("gadget_id", "")
		if gadgetID == "" && (action == actionGetResults || action == actionStopGadget) {
			return mcp.NewToolResultError("A gadget_id must be specified for " + action), nil
		}

		switch action {
		case actionListGadgets:
			return handleListGadgets(ctx, mgr)
		case actionGetResults:
			filter := request.GetString("filter", "")
			groupBy := request.GetString("group_by", "")
			keepBy := request.GetString("keep_by", "")
			return handleGetGadgetResults(ctx, mgr, gadgetID, filter, groupBy, keepBy)
		case actionStopGadget:
			return handleStopGadget(ctx, mgr, gadgetID)
		}

		return mcp.NewToolResultText("Action not implemented"), nil
	}
}

func handleListGadgets(ctx context.Context, mgr gadgetmanager.GadgetManager) (*mcp.CallToolResult, error) {
	log.Debug("Listing gadgets")
	gadgets, err := mgr.ListGadgets(ctx)
	if err != nil {
		return mcp.NewToolResultError("Failed to list gadgets: " + err.Error()), nil
	}
	if len(gadgets) == 0 {
		// an empty list is the common confusion point — the client assumes
		// there is nothing to observe. Point it at the start path explicitly.
		return mcp.NewToolResultText("No running gadgets found. To START a capability, call the gadget_mcp_ebpf_proxy tool with operator.oci.wasm.capability set (e.g. trace_syscall, lock_trace, net_trace, cuda_memtrace); it lists the full catalog and returns results directly."), nil
	}

	JSONData, err := json.Marshal(gadgets)
	if err != nil {
		return mcp.NewToolResultError("Failed to marshal gadgets to JSON: " + err.Error()), nil
	}

	return mcp.NewToolResultText(string(JSONData)), nil
}

// capabilityFromParams extracts the human-readable capability name from a
// GadgetInstance.Params blob (operator.oci.wasm.capability="lock_trace").
// the result buffer is otherwise unattributable — neither the client nor
// any consumer can tell WHICH capability produced a given row set, because the
// only handle is the opaque gadget_id. Echoing the capability lets the client
// reason about coverage ("I have not yet looked with lock_trace").
func capabilityFromParams(params string) string {
	if m := regexp.MustCompile(`operator\.oci\.wasm\.capability="([^"]+)"`).FindStringSubmatch(params); m != nil {
		return m[1]
	}
	return ""
}

func handleGetGadgetResults(ctx context.Context, mgr gadgetmanager.GadgetManager, gadgetID string, filter string, groupBy string, keepBy string) (*mcp.CallToolResult, error) {
	log.Debug("Getting gadget results", "gadget_id", gadgetID)
	result, err := mgr.GetResults(gadgetID, filter, groupBy, keepBy)
	if err != nil {
		// distinguish a transient transport failure (daemon socket
		// momentarily unavailable: EOF / connection refused / reset) from a
		// real, non-retryable error. A bare error previously read identically
		// to "empty result", driving the client into blind retry loops.
		es := err.Error()
		if strings.Contains(es, "EOF") || strings.Contains(es, "connection refused") ||
			strings.Contains(es, "connection reset") || strings.Contains(es, "unavailable") {
			return mcp.NewToolResultError("<transport-error retryable=\"true\">gadget daemon " +
				"momentarily unavailable (" + es + "); retry the same get_results shortly, " +
				"or pivot to another capability if it persists</transport-error>"), nil
		}
		return mcp.NewToolResultError("Failed to get gadget results: " + es), nil
	}
	// prepend a self-describing header so the row set is attributable to
	// a capability + image without the consumer having to parse the param blob.
	if gadgets, lerr := mgr.ListGadgets(ctx); lerr == nil {
		for _, g := range gadgets {
			if g.ID == gadgetID {
				cap := capabilityFromParams(g.Params)
				header := "<gadgetId>" + gadgetID + "</gadgetId>\n" +
					"<gadgetImage>" + g.GadgetImage + "</gadgetImage>\n"
				if cap != "" {
					header += "<capability>" + cap + "</capability>\n"
				}
				result = header + result
				break
			}
		}
	}
	return mcp.NewToolResultText(result), nil
}

func handleStopGadget(_ context.Context, mgr gadgetmanager.GadgetManager, gadgetID string) (*mcp.CallToolResult, error) {
	log.Debug("Stopping gadget", "gadget_id", gadgetID)
	err := mgr.Stop(gadgetID)
	if err != nil {
		return mcp.NewToolResultError("Failed to stop gadget: " + err.Error()), nil
	}
	return mcp.NewToolResultText("Gadget with ID " + gadgetID + " has been stopped"), nil
}
