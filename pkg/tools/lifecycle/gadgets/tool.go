package gadgets

import (
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"github.com/inspektor-gadget/ig-mcp-server/pkg/gadgetmanager"
)

func GetTool(mgr gadgetmanager.GadgetManager) server.ServerTool {
	return server.ServerTool{
		Tool:    lifecycleTool(),
		Handler: lifecycleHandler(mgr),
	}
}

func lifecycleTool() mcp.Tool {
	return mcp.NewTool(
		toolName,
		mcp.WithDescription("Manage ALREADY-RUNNING gadgets (list/get results/stop). this tool does NOT start gadgets. To START a new observation capability (e.g. trace_syscall, lock_trace, cuda_memtrace, net_trace), call the per-image gadget tool (gadget_mcp_ebpf_proxy) and set operator.oci.wasm.capability — that tool enumerates the full capability catalog and returns results directly."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("action",
			mcp.Description("Lifecycle action to perform: "+
				actionListGadgets+"(list running gadgets), "+
				actionStopGadget+"(stop a running gadget using its ID), "+
				actionGetResults+"(get results of a running gadget using its ID, only available before stopping it)"),
			mcp.Enum(gadgetActions...),
		),
		mcp.WithString("gadget_id", mcp.Description("ID of the gadget to stop or get results from, required for "+actionStopGadget+" and "+actionGetResults)),
		mcp.WithString("group_by", mcp.Description("optional aggregation dimension for get_results (one of: syscall, addr, fname, comm; pid/tid/comm resolve through the nested proc object). Returns a top-N table grouped by that field over the FULL pre-truncation set. By default it COUNTS occurrences (e.g. group_by=syscall reveals acquire-vs-release counts such as open vs close to confirm a leak). Append :<numeric_field> to SUM that field per group instead of counting -- e.g. group_by=comm:bytes ranks comms by TOTAL bytes moved and group_by=pid:duration_ns ranks pids by TOTAL time, surfacing a heavy/slow outlier that a plain frequency count would hide")),
		mcp.WithString("keep_by", mcp.Description("optional NUMERIC field name for get_results; when the result overflows the volume cap, retain the records with the LARGEST value of this field (e.g. used_gpu_mem, reserved_unused_bytes, recent_sm_util, duration_ns, size) instead of merely the newest. Use this for magnitude questions — top VRAM holders, slowest syscalls, largest allocations — whose heavy hitters would otherwise be evicted by truncation")),
		mcp.WithString("filter", mcp.Description("optional case-insensitive substring filter for "+actionGetResults+"; keeps only matching records (e.g. a pid, comm, decoded syscall name, or *_op value) BEFORE the volume cap, making the truncation hint actionable on high-volume streams")),
	)
}
