package _default

import (
	"fmt"
	"regexp"
	"strings"
)

// kprobeAttachFailRe matches the gadget-runtime error emitted when an eBPF
// kprobe/kretprobe program cannot be attached to the requested kernel symbol.
// The tracefs layer rejects the probe with EINVAL ("invalid argument") when
// the target function is not present in available_filter_functions — most
// commonly because it is a compiler clone (".constprop.N" / ".isra.N"), is
// inlined, or is otherwise not a valid kprobe target. The raw error surfaced
// to the MCP client as an opaque JSON-RPC -32603 "internal error", which gives
// the agent no actionable signal and makes it retry the SAME
// un-attachable symbol (seen when a gcc .constprop clone is requested).
//
// Stable substrings across runtime versions:
//
//	attaching eBPF program "<prog>": creating tracefs event ... : ... write
//	/sys/kernel/tracing/kprobe_events: invalid argument
var kprobeAttachFailRe = regexp.MustCompile(
	`attaching eBPF program .*(?:creating tracefs event|kprobe_events).*invalid argument`)

// kprobeSymbolRe extracts the offending kernel symbol from the runtime error's
// `fallback for "<symbol>"` clause so the diagnostic can name it and detect
// compiler-clone suffixes.
var kprobeSymbolRe = regexp.MustCompile(`fallback for "([^"]+)"`)

// cloneSuffixRe detects GCC clone suffixes that are frequently NOT attachable:
//
//	__alloc_pages_slowpath.constprop.0   foo.isra.0   bar.part.0   baz.cold
var cloneSuffixRe = regexp.MustCompile(`\.(constprop|isra|part|cold)(\.\d+)?$`)

// isKprobeAttachFailure reports whether err is the kprobe/kretprobe
// symbol-attach EINVAL class described above.
func isKprobeAttachFailure(err error) bool {
	if err == nil {
		return false
	}
	return kprobeAttachFailRe.MatchString(err.Error())
}

// kprobeAttachDiagnostic turns a raw kprobe-attach failure into a structured,
// actionable message for the MCP client. It names the un-attachable symbol,
// explains WHY (compiler clone / not in available_filter_functions), and tells
// the agent explicitly NOT to retry the same symbol — pick an attachable one.
// Returning this as a normal ToolResult (rather than a transport -32603) lets
// the agent reason about the failure and pivot, exactly as the server-side
// result-shaping change did for the "output too large" -32603 class.
func kprobeAttachDiagnostic(image string, err error) string {
	raw := err.Error()
	sym := ""
	if m := kprobeSymbolRe.FindStringSubmatch(raw); m != nil {
		sym = m[1]
	}
	var b strings.Builder
	b.WriteString("<kprobe-attach-error>\n")
	if sym != "" {
		b.WriteString(fmt.Sprintf("The kernel symbol %q is NOT attachable as a kprobe/kretprobe on this host.\n", sym))
	} else {
		b.WriteString("The requested kernel symbol is NOT attachable as a kprobe/kretprobe on this host.\n")
	}
	if sym != "" && cloneSuffixRe.MatchString(sym) {
		base := cloneSuffixRe.ReplaceAllString(sym, "")
		b.WriteString(fmt.Sprintf(
			"Reason: %q is a compiler clone (%s suffix) produced by GCC optimization; such clones are usually inlined and absent from /sys/kernel/tracing/available_filter_functions, so tracefs rejects the probe with EINVAL.\n",
			sym, cloneSuffixRe.FindString(sym)))
		b.WriteString(fmt.Sprintf(
			"Try the canonical (non-clone) symbol %q instead, or a stable nearby tracepoint.\n", base))
	} else {
		b.WriteString("Reason: the symbol is not present in /sys/kernel/tracing/available_filter_functions (inlined, renamed, or not a valid kprobe target), so tracefs rejects the probe with EINVAL.\n")
	}
	b.WriteString("DO NOT retry the same symbol — it will fail identically. Choose a function that appears in available_filter_functions, or use a tracepoint-based capability.\n")
	b.WriteString("</kprobe-attach-error>")
	return b.String()
}
