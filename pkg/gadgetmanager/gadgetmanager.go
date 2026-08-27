// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gadgetmanager

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/environment"
	"k8s.io/cli-runtime/pkg/genericclioptions"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

const maxResultLen = 64 * 1024 // 64kb

// maxUncapResultLen bounds an EXPLICIT caller uncap (operator.limiter.max-entries<0)
// to a finite ceiling. Lifting the cap to len+1 (unbounded) let a multi-hundred-MB
// runq_lat-class stream reach encoding/json.Marshal, whose escaping of ~300MB
// exceeded the MCP client 40s timeout and surfaced as a daemon "hang" (the
// stdio transport wedged). 8MB JSON-escapes in well under a second.
const maxUncapResultLen = 8 * 1024 * 1024 // 8MB transport ceiling for explicit uncap

// GadgetManager is an interface for managing gadgets.
type GadgetManager interface {
	// Run starts a gadget with the given image and parameters, returning the output as a string.
	Run(image string, params map[string]string, timeout time.Duration) (string, error)
	// RunDetached starts a gadget with the given image and parameters in the background, returning its ID.
	RunDetached(image string, params map[string]string) (string, error)
	// GetResults returns the stored result buffer from a gadget.
	// filter is an optional case-insensitive substring; when non-empty
	// only matching newline-delimited records are kept (applied BEFORE
	// truncation so the truncation count reflects the filtered set). This makes
	// the truncation <hint> ('re-run with a tighter filter') actionable.
	GetResults(id string, filter string, groupBy string, keepBy string) (string, error)
	// Stop stops a gadget
	Stop(id string) error
	// GetInfo retrieves information about a gadget image via runtime.
	GetInfo(ctx context.Context, image string) (*api.GadgetInfo, error)
	// GetVersion retrieves the version of Inspektor Gadget installed in the cluster
	GetVersion() (string, error)
	// ListGadgets lists all running gadget instances
	ListGadgets(ctx context.Context) ([]*GadgetInstance, error)
}

// GadgetInstance represents a running gadget instance
type GadgetInstance struct {
	ID          string `json:"id"`
	GadgetImage string `json:"gadgetImage"`
	Params      string `json:"params"`
	CreatedBy   string `json:"createdBy,omitempty"`
	StartedAt   string `json:"startedAt,omitempty"`
}

type gadgetManager struct {
	k8sConfig       *genericclioptions.ConfigFlags
	formatterMu     sync.Mutex
	env             string
	remoteAddr      string
	gadgetNamespace string

	// scoping fix: remember the capability each DETACHED instance was launched with.
	// GetResults does not re-supply launch params, so without this the detached
	// read path falls back to capability="" and the GPU/lock/mm rows the client
	// selected are evicted from the keep-set by the always-on fs/net flood.
	instanceMu    sync.Mutex
	instanceCaps  map[string]string
	instanceUncap map[string]bool
}

// NewGadgetManager creates a new GadgetManager instance.
func NewGadgetManager(env string, linuxRemoteAddress string, k8sConfig *genericclioptions.ConfigFlags, gadgetNamespace string) (GadgetManager, error) {
	if env != "kubernetes" && env != "linux" {
		return nil, fmt.Errorf("unsupported gadget manager environment: %s", env)
	}
	if env == "linux" && linuxRemoteAddress == "" {
		return nil, fmt.Errorf("linuxRemoteAddress must be set when environment is linux")
	}
	return &gadgetManager{
		k8sConfig:       k8sConfig,
		env:             env,
		remoteAddr:      linuxRemoteAddress,
		gadgetNamespace: gadgetNamespace,
		instanceCaps:    make(map[string]string),
		instanceUncap:   make(map[string]bool),
	}, nil
}

func (g *gadgetManager) Run(image string, params map[string]string, timeout time.Duration) (string, error) {
	// Capture the EXPLICIT-caller transport-uncap intent, then strip the
	// server-internal sentinel so the gadget runtime never sees a non-gadget key.
	uncap := limiterUncapped(params)
	delete(params, TransportUncapKey)
	var res strings.Builder
	gadgetCtx := gadgetcontext.New(
		context.Background(),
		image,
		gadgetcontext.WithDataOperators(
			g.outputOperator(func(buf []byte) {
				res.Write(buf)
				res.WriteByte('\n')
			}),
		),
		gadgetcontext.WithTimeout(timeout),
	)

	runtime, err := g.getRuntime()
	if err != nil {
		return "", fmt.Errorf("getting runtime: %w", err)
	}

	if err = runtime.RunGadget(gadgetCtx, runtime.ParamDescs().ToParams(), params); err != nil {
		return "", fmt.Errorf("running gadget: %w", err)
	}
	// scoping fix: scope truncation/summary to the selected capability so its rows
	// survive the always-on fs/net flood.
	capability := params["operator.oci.wasm.capability"]
	return truncateResultsKeep(res.String(), false, "", capability, "", uncap), nil
}

func (g *gadgetManager) RunDetached(image string, params map[string]string) (string, error) {
	uncap := limiterUncapped(params)
	delete(params, TransportUncapKey)
	gadgetCtx := gadgetcontext.New(
		context.Background(),
		image,
	)
	runtime, err := g.getRuntime()
	if err != nil {
		return "", fmt.Errorf("getting runtime: %w", err)
	}

	p := runtime.ParamDescs().ToParams()

	newID := make([]byte, 16)
	rand.Read(newID)
	idString := hex.EncodeToString(newID)

	p.Set(grpcruntime.ParamTags, "createdBy=ig-mcp-server")
	p.Set(grpcruntime.ParamID, idString)
	p.Set(grpcruntime.ParamDetach, "true")
	if err = runtime.RunGadget(gadgetCtx, p, params); err != nil {
		return "", fmt.Errorf("running gadget: %w", err)
	}
	// scoping fix: remember the capability so a later detached GetResults can scope
	// its keep-set + topGroups summary to this instance's datasource.
	g.instanceMu.Lock()
	g.instanceCaps[idString] = params["operator.oci.wasm.capability"]
	g.instanceUncap[idString] = uncap
	g.instanceMu.Unlock()
	return idString, nil
}

func (g *gadgetManager) Stop(id string) error {
	runtime, err := g.getRuntime()
	if err != nil {
		return fmt.Errorf("getting runtime: %w", err)
	}
	if err = runtime.RemoveGadgetInstance(context.Background(), runtime.ParamDescs().ToParams(), id); err != nil {
		return fmt.Errorf("stopping to gadget: %w", err)
	}
	// scoping fix: drop the remembered capability for this instance.
	g.instanceMu.Lock()
	delete(g.instanceCaps, id)
	delete(g.instanceUncap, id)
	g.instanceMu.Unlock()
	return nil
}

func (g *gadgetManager) GetResults(id string, filter string, groupBy string, keepBy string) (string, error) {
	var res strings.Builder
	to, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	gadgetCtx := gadgetcontext.New(
		to,
		id,
		gadgetcontext.WithDataOperators(
			g.outputOperator(func(buf []byte) {
				res.Write(buf)
				res.WriteByte('\n')
			}),
		),
		gadgetcontext.WithID(id),
		gadgetcontext.WithUseInstance(true),
		gadgetcontext.WithTimeout(time.Second),
	)

	runtime, err := g.getRuntime()
	if err != nil {
		return "", fmt.Errorf("getting runtime: %w", err)
	}

	if err = runtime.RunGadget(gadgetCtx, runtime.ParamDescs().ToParams(), map[string]string{}); err != nil {
		return "", fmt.Errorf("attaching to gadget: %w", err)
	}
	// scoping fix: detached GetResults path — the capability is not re-supplied on the
	// instance fetch, so recover it from the launch-time map and scope the
	// keep-set + topGroups summary to that capability's datasource (otherwise
	// the requested GPU/lock/mm rows are evicted by the always-on fs/net flood).
	g.instanceMu.Lock()
	capability := g.instanceCaps[id]
	uncapped := g.instanceUncap[id]
	g.instanceMu.Unlock()
	return truncateResultsKeep(applyScopeOrFilter(res.String(), filter), true, groupBy, capability, keepBy, uncapped), nil
}

// filterRecords keeps only newline-delimited records that contain the given
// case-insensitive substring. Empty filter is a no-op. lets the client
// act on the truncation hint by narrowing to pid=/syscall=/op=/comm matches
// server-side, so an 800k-row stream collapses to the relevant slice instead
// of being blindly clipped to the newest ~100 rows.
func filterRecords(results, filter string) string {
	if filter == "" {
		return results
	}
	needle := strings.ToLower(filter)
	var b strings.Builder
	for _, line := range strings.Split(results, "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), needle) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// ---: structured scope filter / datasource isolation
//
// filterRecords is a blunt case-insensitive SUBSTRING match. A process-identity
// scope such as `proc.comm==DIAG_case43` or `pid==4242` therefore (1) never
// matched the JSON `"comm":"DIAG_case43"` literally (the `==` and the key order
// differ) and (2) let through records from OTHER datasources that carry no
// process identity at all (the always-on fs/net flood), so a per-comm scope
// "returned 0 of my target while suppressedUnrelated sat in the thousands"
// (a representative workload). scopeRecords fixes both by parsing the identity predicate
// and matching it against the record's RESOLVED field (via lookupField, which
// already understands bare aliases and the nested proc.* object). Records that
// do not carry the scoped identity field are DROPPED — that IS the datasource
// isolation: when you scope by comm/pid you only want rows that HAVE that
// identity, not unrelated-family noise. This is a pure userspace result-shaping
// change; the in-kernel emit path is untouched.

// scopePredicate is a single parsed identity predicate (field op value).
type scopePredicate struct {
	field string // canonical key handed to lookupField (pid, comm, proc.pid, ...)
	op    string // "==", "!=", "~"
	value string
}

// identityScopeFields are the process-identity dimensions a scope predicate may
// target. Restricting to this allowlist keeps free-form filters (fname==/etc,
// syscall~openat, multi-term expressions) on the legacy substring path.
var identityScopeFields = map[string]bool{
	"pid": true, "tid": true, "comm": true, "ppid": true,
	"uid": true, "gid": true, "mntns_id": true,
}

// parseScopePredicate recognises EXACTLY one identity predicate of the form
// <field><op><value> where op is ==, != or ~ and field is an identity alias
// (pid/comm/...) or an explicit proc.* dotted path. Returns ok=false for
// anything else so the caller keeps the legacy substring filter for it.
func parseScopePredicate(filter string) (scopePredicate, bool) {
	f := strings.TrimSpace(filter)
	if f == "" {
		return scopePredicate{}, false
	}
	// A second predicate / boolean term means "not a single identity scope".
	if strings.ContainsAny(f, " \t") || strings.Contains(f, "&&") || strings.Contains(f, ",") {
		return scopePredicate{}, false
	}
	// Operator order matters: != before == before ~ (single char).
	var op string
	var idx int
	for _, cand := range []string{"!=", "==", "~"} {
		if i := strings.Index(f, cand); i > 0 {
			op, idx = cand, i
			break
		}
	}
	if op == "" {
		return scopePredicate{}, false
	}
	lhs := strings.TrimSpace(f[:idx])
	rhs := strings.TrimSpace(f[idx+len(op):])
	if lhs == "" || rhs == "" {
		return scopePredicate{}, false
	}
	// Validate LHS is an identity field (bare alias or proc.* dotted path).
	leaf := lhs
	if strings.Contains(lhs, ".") {
		parts := strings.Split(lhs, ".")
		leaf = parts[len(parts)-1]
		if parts[0] != "proc" { // only proc.* paths are identity scopes
			return scopePredicate{}, false
		}
	}
	if !identityScopeFields[leaf] {
		return scopePredicate{}, false
	}
	return scopePredicate{field: lhs, op: op, value: rhs}, true
}

// scopeMatch reports whether a resolved field value satisfies the predicate.
func (p scopePredicate) scopeMatch(v interface{}) bool {
	s := fmt.Sprintf("%v", v)
	switch p.op {
	case "==":
		return s == p.value
	case "!=":
		return s != p.value
	case "~":
		return strings.Contains(strings.ToLower(s), strings.ToLower(p.value))
	}
	return false
}

// scopeRecords keeps only the newline-delimited JSON records whose RESOLVED
// identity field satisfies the predicate. Records that do not carry the scoped
// field are dropped (datasource isolation). Returns the kept records joined by
// newlines (trailing newline preserved like filterRecords).
func scopeRecords(results string, p scopePredicate) string {
	var b strings.Builder
	for _, line := range strings.Split(results, "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			continue // non-JSON line: cannot scope on identity, drop from a scope
		}
		v, ok := lookupField(m, p.field)
		if !ok {
			continue // record lacks the scoped identity -> unrelated family, drop
		}
		if p.scopeMatch(v) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// applyScopeOrFilter dispatches: a structured identity predicate gets the
// JSON-aware scopeRecords (datasource isolation); everything else keeps the
// legacy substring filterRecords. Empty filter is a no-op in both paths.
func applyScopeOrFilter(results, filter string) string {
	if p, ok := parseScopePredicate(filter); ok {
		return scopeRecords(results, p)
	}
	return filterRecords(results, filter)
}

func (g *gadgetManager) GetInfo(ctx context.Context, image string) (*api.GadgetInfo, error) {
	gadgetCtx := gadgetcontext.New(
		ctx,
		image,
	)

	runtime, err := g.getRuntime()
	if err != nil {
		return nil, fmt.Errorf("getting runtime: %w", err)
	}

	info, err := runtime.GetGadgetInfo(gadgetCtx, runtime.ParamDescs().ToParams(), nil)
	if err != nil {
		return nil, fmt.Errorf("get gadget info: %w", err)
	}
	return info, nil
}

func (g *gadgetManager) ListGadgets(ctx context.Context) ([]*GadgetInstance, error) {
	rt, err := g.getRuntime()
	if err != nil {
		return nil, fmt.Errorf("getting runtime: %w", err)
	}

	instances, err := rt.GetGadgetInstances(ctx, rt.ParamDescs().ToParams())
	if err != nil {
		return nil, fmt.Errorf("listing gadgets: %w", err)
	}

	var gadgetInstances []*GadgetInstance
	for _, instance := range instances {
		inst := gadgetInstanceFromAPI(instance)
		if inst != nil {
			gadgetInstances = append(gadgetInstances, inst)
		}
	}
	return gadgetInstances, nil
}

func (g *gadgetManager) GetVersion() (string, error) {
	rt, err := g.getRuntime()
	if err != nil {
		return "", fmt.Errorf("getting runtime: %w", err)
	}

	info, err := rt.GetInfo()
	if err != nil {
		return "", fmt.Errorf("getting info: %w", err)
	}
	return info.ServerVersion, nil
}

// --- scoping fix: capability-scoped result assembly --------------------------------
//
// Selecting a capability (operator.oci.wasm.capability) controls which eBPF
// programs ATTACH but not which datasources EMIT into the shared result buffer.
// The always-on fs/net streaming datasources out-produce the low-rate GPU/mm
// snapshot rows, so without scoping they fill the truncation window first and
// the REQUESTED rows are evicted before the summarizer runs. The tables below
// let the assembler (1) prioritise the selected capability's own records in the
// truncation keep-set and (2) key the topGroups summary on the capability's
// natural field instead of always fname.

// capabilitySigFields maps a capability to the discriminator field(s) that only
// records from THAT capability's datasource carry. A record is "in-family" for
// the selected capability if it contains any of these keys. Always-on fs/net
// records (fname / net_op / saddr...) do not carry these, so they sort after.
var capabilitySigFields = map[string][]string{
	"cuda_memsnapshot": {"memsnap_op", "gpu_pid", "dev_used", "dev_free", "dev_total", "used_gpu_mem", "recent_sm_util", "reserved_unused_bytes"},
	"cuda_smutil":      {"smutil_op", "sm_util", "smu_pid", "mem_util"},
	"cuda_profile":     {"gpu_op", "duration_ns", "gx", "bx"},
	"cuda_memtrace":    {"is_runtime", "op", "ptr", "size"},
	"mm_trace":         {"mm_op"},
	"net_trace":        {"net_op", "connect_latency_ns", "retrans_out", "tcp_state"},
	"fs_trace":         {"fs_op", "fname"},
	"lock_trace":       {"lock_op", "addr", "holder_tid"},
	"heap_profile":     {"heap_op", "old_ptr"},
	"irq_trace":        {"vec"},
	"block_io":         {"req_op", "queue_depth", "sector"},
	"runq_lat":         {"runq_ns", "cpu"},
	"trace_syscall":    {"syscall"},
}

// capabilityGroupKey maps a capability to the field topGroups should aggregate
// on (the capability's NATURAL dimension). Falls back to the generic priority
// list when a capability is not listed or its key is absent from the records.
var capabilityGroupKey = map[string]string{
	"cuda_memsnapshot": "gpu_pid",
	"cuda_smutil":      "smu_pid",
	"cuda_profile":     "gpu_op",
	"cuda_memtrace":    "op",
	"mm_trace":         "mm_op",
	"net_trace":        "net_op",
	"fs_trace":         "fs_op",
	"lock_trace":       "addr",
	"heap_profile":     "heap_op",
	"irq_trace":        "vec",
	"block_io":         "dev",
	"runq_lat":         "cpu",
	"trace_syscall":    "syscall",
}

// recordInFamily reports whether a single newline-delimited JSON record carries
// any of the selected capability's signature fields. Uses a cheap substring
// probe (the buffer is one compact JSON object per line) to avoid parsing every
// record twice on the hot truncation path.
func recordInFamily(line string, sigs []string) bool {
	for _, s := range sigs {
		if strings.Contains(line, "\""+s+"\"") {
			return true
		}
	}
	return false
}

// recordCount returns the number of newline-delimited JSON records in s (0 for
// empty). Used by the capability-scoped keep-set to report how many in-family
// vs suppressed flood records a window held.
func recordCount(s string) int {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// capabilityInFamilyCount returns how many of the supplied records carry the
// selected capability's signature fields. For a known capability it counts the
// in-family records via the same partition used for flood suppression; for an
// unknown or empty capability no scoping applies so every record counts. This
// makes the active truncation branch self-verifying: when <inFamilyRecords>
// equals <keptRecords> the kept set is ENTIRELY in-family (the always-on flood
// was fully suppressed and in-family records SURVIVED the positional/numeric
// cut). Previously the active branch only proved this implicitly via the
// topGroups sum; an MCP client had to do the arithmetic by hand.
func capabilityInFamilyCount(records, capability string) int {
	if capability == "" {
		return recordCount(records)
	}
	if _, known := capabilitySigFields[capability]; !known {
		return recordCount(records)
	}
	inFam, _ := partitionByCapability(records, capability)
	return recordCount(inFam)
}

// partitionByCapability splits newline-delimited JSON records into the selected
// capability's in-family records and everything else (the always-on fs/net
// noise), preserving original order within each group. Returns (inFamily,
// others). When cap is unknown/empty both signatures are nil and everything is
// "other" (caller then keeps legacy behaviour).
func partitionByCapability(results, capability string) (string, string) {
	sigs := capabilitySigFields[capability]
	if len(sigs) == 0 {
		return "", results
	}
	var inFam, other strings.Builder
	for _, ln := range strings.Split(strings.TrimRight(results, "\n"), "\n") {
		t := strings.TrimSpace(ln)
		if t == "" || t[0] != '{' {
			continue
		}
		if recordInFamily(t, sigs) {
			inFam.WriteString(ln)
			inFam.WriteByte('\n')
		} else {
			other.WriteString(ln)
			other.WriteByte('\n')
		}
	}
	return inFam.String(), other.String()
}

// lookupField resolves a (possibly nested or aliased) field name against a
// decoded record. It supports three forms so an client can group_by a process-
// identity dimension that several streaming gadgets nest under "proc" rather than
// expose at top level: (1) a flat top-level field (addr, duration_ns, syscall);
// (2) an explicit dotted path (proc.pid, proc.parent.comm); (3) a bare alias
// (pid/tid/comm/mntns_id/uid/gid) carried inside the nested "proc" (and, for
// uid/gid, "proc.creds") object. Without alias/dotted support a group_by=pid over
// a 1.6M-record lock_trace stream silently matched nothing and forced the client
// to hand-parse the clipped raw sample instead of reading a full-set aggregate
// (a representative workload: lock_trace 1,635,196 records clipped to "oldest 95").
func lookupField(m map[string]interface{}, key string) (interface{}, bool) {
	if v, ok := m[key]; ok { // flat top-level
		return v, true
	}
	if strings.Contains(key, ".") { // explicit dotted path
		return lookupDotted(m, key)
	}
	switch key { // bare alias nested under proc / proc.creds
	case "pid", "tid", "comm", "mntns_id", "ppid":
		if proc, ok := m["proc"].(map[string]interface{}); ok {
			if v, ok := proc[key]; ok {
				return v, true
			}
			if key == "ppid" {
				if par, ok := proc["parent"].(map[string]interface{}); ok {
					if v, ok := par["pid"]; ok {
						return v, true
					}
				}
			}
		}
	case "uid", "gid", "user", "group":
		if proc, ok := m["proc"].(map[string]interface{}); ok {
			if creds, ok := proc["creds"].(map[string]interface{}); ok {
				if v, ok := creds[key]; ok {
					return v, true
				}
			}
		}
	}
	return nil, false
}

// lookupDotted walks a dotted path (proc.pid, proc.parent.comm) through the
// nested map[string]interface{} levels produced by json.Decode.
func lookupDotted(m map[string]interface{}, path string) (interface{}, bool) {
	parts := strings.Split(path, ".")
	var cur interface{} = m
	for _, p := range parts {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return nil, false
		}
		cur, ok = mm[p]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// topGroupsSummary computes a server-side group-by frequency table over the
// FULL (pre-truncation) newline-delimited JSON so an client can see the DOMINANT
// contributor of a high-volume streaming capability (lock_trace, trace_syscall,
// runq_lat,...) without client-side parsing of a clipped sample. The grouping
// key is chosen by priority from fields actually present in the records:
// addr (contended lock word) > syscall (decoded name) > fname (file) > comm
// (process). Returns "" if no usable key is found (so the block is omitted).
// asFloat coerces a decoded JSON value (json.Number via UseNumber, float64,
// or a numeric string) to a float64 for sum_by aggregation. Non-numeric values
// report ok=false so a record that lacks the metric is skipped, not summed as 0.
func asFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case float64:
		return t, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case string:
		if t == "" {
			return 0, false
		}
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	}
	return 0, false
}

// fmtFloat renders a summed metric without scientific notation: integral sums
// (the common case -- bytes, duration_ns) print as plain integers, fractional
// sums keep up to 3 decimals. Mirrors the UseNumber intent of keeping numbers
// human/grep friendly in the wire output.
func fmtFloat(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', 3, 64)
}

// splitGroupBy parses a group_by token of the form "dimension" or
// "dimension:metric". When a metric is present the summary SUMS that numeric
// field per dimension value and ranks groups by the sum (suggestion 119/235:
// "top-N by summed bytes per pid", "duration_ns rollup by comm/tid"); otherwise
// it is an ordinary frequency-count group_by. The metric may itself be a nested
// alias (pid/proc.* style) resolved through lookupField.
func splitGroupBy(forced string) (dim string, metric string) {
	if i := strings.IndexByte(forced, ':'); i >= 0 {
		return strings.TrimSpace(forced[:i]), strings.TrimSpace(forced[i+1:])
	}
	return forced, ""
}

func topGroupsSummary(results string, forced string, capability string) string {
	type kv struct {
		k string
		n int
	}
	// candidate keys in priority order; group_by (forced) overrides selection so
	// the client can pick the aggregation dimension (e.g. group_by=syscall to see
	// acquire vs release counts -- open=N vs close=M -- and confirm a leak).
	keys := []string{"addr", "syscall", "fname", "comm"}
	// scoping fix: lead with the selected capability's natural grouping dimension
	// (cuda_op/mm_op/syscall/gpu_pid/...) so a GPU/mm snapshot is not summarised
	// by the always-on fs "fname" field. forced (group_by=) still wins.
	if k, ok := capabilityGroupKey[capability]; ok && k != "" {
		keys = append([]string{k}, keys...)
	}
	// sum_by: group_by="dimension:metric" sums <metric> per <dimension> and
	// ranks by the SUM instead of the record COUNT (suggestion 119/235).
	dim, metric := splitGroupBy(forced)
	if dim != "" {
		keys = []string{dim}
	}
	// Dedupe: the capability's natural key may already be one of the default
	// candidates (addr for lock_trace, syscall for trace_syscall). Without this
	// the duplicated key is iterated twice per record below and every count is
	// doubled (a misleading "openat count=4" for 2 real records). Stable, first
	// occurrence wins so the priority order is preserved.
	if len(keys) > 1 {
		seen := make(map[string]bool, len(keys))
		uniq := keys[:0:0]
		for _, k := range keys {
			if !seen[k] {
				seen[k] = true
				uniq = append(uniq, k)
			}
		}
		keys = uniq
	}
	counts := map[string]map[string]int{}
	// sums[k][groupValue] = running total of <metric> for that group; only
	// populated when a sum_by metric was supplied (dimension:metric form).
	sums := map[string]map[string]float64{}
	for _, k := range keys {
		counts[k] = map[string]int{}
		sums[k] = map[string]float64{}
	}
	// scoping fix: scope the summary to the selected capability's IN-FAMILY
	// records. Leading the key list with the natural field is not enough: when
	// that field is empty in this window (e.g. a cuda_memsnapshot run that
	// captured no GPU rows, only the always-on fs/net flood), `chosen` would fall
	// through to the flood's fname and the summary would be silently keyed on an
	// unrelated capability (the live `<topGroups key="fname">` regression). Count
	// only the capability's own datasource records so the block is either keyed on
	// the capability's dimension or omitted entirely. A forced group_by= still
	// operates over the full set (the client explicitly chose that dimension), and
	// an unknown capability (no signature fields) keeps legacy behaviour.
	scoped := results
	if capability != "" && forced == "" {
		if sigs := capabilitySigFields[capability]; len(sigs) > 0 {
			inFam, _ := partitionByCapability(results, capability)
			if inFam == "" {
				return ""
			}
			scoped = inFam
		}
	}
	lines := strings.Split(strings.TrimRight(scoped, "\n"), "\n")
	parsed := 0
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || ln[0] != '{' {
			continue
		}
		var m map[string]interface{}
		// UseNumber keeps integer natural keys (dev, addr, cpu, vec, gpu_pid,
		// smu_pid) as exact-digit strings. Plain json.Unmarshal decodes every
		// JSON number to float64, so a device id 271581185 renders as
		// "2.71581185e+08" -- useless for reconciliation/grouping (
		// 25510/25512 dev-key gap surfaced this).
		dec := json.NewDecoder(strings.NewReader(ln))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			continue
		}
		parsed++
		for _, k := range keys {
			if v, ok := lookupField(m, k); ok {
				s := fmt.Sprintf("%v", v)
				if s != "" && s != "0" && s != "<nil>" {
					counts[k][s]++
					// sum_by: add this record's <metric> to the group's running
					// total. A record missing/zero on the metric contributes
					// nothing (asFloat ok=false) but still counts toward the
					// frequency, so distinct group membership is preserved.
					if metric != "" {
						if mv, mok := lookupField(m, metric); mok {
							if f, fok := asFloat(mv); fok {
								sums[k][s] += f
							}
						}
					}
				}
			}
		}
	}
	if parsed == 0 {
		return ""
	}
	// pick the first priority key that actually grouped anything
	var chosen string
	for _, k := range keys {
		if len(counts[k]) > 0 {
			chosen = k
			break
		}
	}
	if chosen == "" {
		return ""
	}
	type kvs struct {
		k string
		n int
		s float64
	}
	var arr []kvs
	for k, n := range counts[chosen] {
		arr = append(arr, kvs{k, n, sums[chosen][k]})
	}
	useSum := metric != ""
	sort.Slice(arr, func(i, j int) bool {
		if useSum {
			// rank by summed metric desc, tie-break by count then key so the
			// ordering is deterministic (suggestion 119: surface the slow
			// leaker = the largest SUMMED bytes, not the most frequent op).
			if arr[i].s != arr[j].s {
				return arr[i].s > arr[j].s
			}
		}
		if arr[i].n != arr[j].n {
			return arr[i].n > arr[j].n
		}
		return arr[i].k < arr[j].k
	})
	if len(arr) > 10 {
		arr = arr[:10]
	}
	var b strings.Builder
	if useSum {
		fmt.Fprintf(&b, "<topGroups key=\"%s\" sum_of=\"%s\" distinct=\"%d\">", chosen, metric, len(counts[chosen]))
		for _, e := range arr {
			fmt.Fprintf(&b, "\n  %s=%s sum_%s=%s count=%d", chosen, e.k, metric, fmtFloat(e.s), e.n)
		}
	} else {
		fmt.Fprintf(&b, "<topGroups key=\"%s\" distinct=\"%d\">", chosen, len(counts[chosen]))
		for _, e := range arr {
			fmt.Fprintf(&b, "\n  %s=%s count=%d", chosen, e.k, e.n)
		}
	}
	b.WriteString("\n</topGroups>\n")
	return b.String()
}

func markAggregateComplete(summary string) string {
	if summary == "" {
		return ""
	}
	return summary + "<aggregateComplete>true</aggregateComplete>\n"
}

// groupableFields scans the newline-delimited JSON records and returns a
// comma-separated, de-duplicated list of the field names an client can pass to
// group_by= in this window: every top-level scalar key plus the resolvable
// process-identity aliases (pid/tid/comm/...) when a nested "proc" object is
// present. Used to answer "you asked group_by=X but X is not here; these are".
func groupableFields(results string) string {
	seen := map[string]bool{}
	order := []string{}
	add := func(k string) {
		if k == "" || seen[k] {
			return
		}
		seen[k] = true
		order = append(order, k)
	}
	n := 0
	for _, line := range strings.Split(results, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var m map[string]interface{}
		dec := json.NewDecoder(strings.NewReader(line))
		dec.UseNumber()
		if err := dec.Decode(&m); err != nil {
			continue
		}
		for k, v := range m {
			switch v.(type) {
			case map[string]interface{}:
				if k == "proc" { // expose the identity aliases the client can use
					for _, alias := range []string{"comm", "pid", "tid", "ppid"} {
						if _, ok := lookupField(m, alias); ok {
							add(alias)
						}
					}
				}
			case []interface{}:
				// skip array columns: not a scalar group dimension
			default:
				add(k)
			}
		}
		n++
		if n >= 200 { // a sample is enough to enumerate the schema
			break
		}
	}
	sort.Strings(order)
	return strings.Join(order, ", ")
}

// TransportUncapKey is a SERVER-INTERNAL signal (NOT a gadget param) set by the
// tool handler ONLY when the CALLER explicitly passes operator.limiter.max-entries<0.
// limiterUncapped keys off this sentinel rather than the limiter value directly,
// because defaultParamsFromGadgetInfo seeds the gadget's REQUIRED max-entries with
// its own default "-1" on EVERY call (the limiter operator errors if the param is
// absent). Reading that value made limiterUncapped true universally, disabling the
// 64KB transport cap and marshaling the full (up to ~300MB) stream, whose
// JSON-escaping exceeded the client 40s timeout and surfaced as a daemon "hang".
// The sentinel is STRIPPED from the param map before the gadget runtime sees it.
const TransportUncapKey = "__mcp.server.transport-uncap"

// limiterUncapped reports whether the CALLER explicitly requested that the
// server-side 64KB transport re-clip be lifted (to the finite maxUncapResultLen
// ceiling). True only when the handler set TransportUncapKey from an explicit
// caller operator.limiter.max-entries<0 -- the gadget's seeded DEFAULT -1 does
// NOT count (see TransportUncapKey).
func limiterUncapped(params map[string]string) bool {
	return params[TransportUncapKey] == "true"
}

// truncateResultsKeep is truncateResults plus an optional numeric retention
// mode. keepBy names a numeric field; when set (and the output overflows) the
// records with the LARGEST value of that field are retained instead of merely
// the newest/oldest, so magnitude answers (top VRAM holders, slowest syscalls,
// largest allocations) survive the cap. keepBy="" is byte-for-byte the legacy
// behaviour.
func truncateResultsKeep(results string, latest bool, groupBy string, capability string, keepBy string, uncap ...bool) string {
	// Fix (review feedback, Part-1 "max-entries=-1 cap-disablement"): a
	// caller that explicitly passed operator.limiter.max-entries=-1 (the
	// documented "no limit" sentinel -- observed in practice
	// started a background fs_trace with operator.limiter.max-entries=-1 to
	// request the COMPLETE record set) has the server-side 64KB re-clip
	// LIFTED, so the full stream is returned instead of being silently
	// truncated a SECOND time on top of what the client already un-limited.
	// Capability scoping, group_by aggregation and keep_by retention all still
	// apply; only the positional byte cap is disabled. Default (no opt/false)
	// is byte-for-byte the legacy 64KB behaviour, so existing callers/tests
	// are unaffected.
	effCap := maxResultLen
	unc := len(uncap) > 0 && uncap[0]
	if unc {
		// Explicit caller uncap, BOUNDED to a finite ceiling so a pathological
		// multi-hundred-MB stream cannot reach encoding/json.Marshal and wedge the
		// MCP stdio transport (escaping ~300MB exceeded the client 40s timeout).
		effCap = maxUncapResultLen
	}
	// scoping fix ( suggestion #3 + Part-1 item b): when a KNOWN capability is
	// selected, SCOPE the result body to that capability's own datasource and
	// SUPPRESS the always-on fs/net flood (count it, do not dump it). Without
	// this, an idle-target window returns up to maxResultLen of unrelated
	// tailscaled/UDP/fs records and the client never learns that ZERO in-family
	// records were captured (observed in practice
	// selected, 4010 records, 101 kept — ALL net_udp_recv, zero GPU). The
	// reorder-only predecessor merely floated in-family rows to the kept side of
	// the byte cut, which is a no-op when the capability emitted nothing.
	if capability != "" {
		if _, known := capabilitySigFields[capability]; known {
			inFam, other := partitionByCapability(results, capability)
			if suppressed := recordCount(other); suppressed > 0 {
				if recordCount(inFam) == 0 {
					// The capability emitted nothing in this window. Say so
					// plainly instead of returning the unrelated flood.
					return fmt.Sprintf("\n<isTruncated>true</isTruncated>\n"+
						"<scopedTo>%s</scopedTo>\n"+
						"<inFamilyRecords>0</inFamilyRecords>\n"+
						"<suppressedUnrelated>%d</suppressedUnrelated>\n"+
						"<hint>no %s records were captured in this window; %d "+
						"unrelated always-on fs/net records were suppressed. The "+
						"selected capability emitted nothing — the target is "+
						"likely idle, or attach/pull did not take. Re-run with a "+
						"longer duration, or verify the workload is active.</hint>\n"+
						"<results></results>\n", capability, suppressed, capability, suppressed)
				}
				// In-family records exist alongside flood: scope to them and reuse
				// the standard cut/keep machinery by recursing on the in-family
				// slice (which carries no flood, so this branch is not re-entered),
				// then annotate with the suppressed-flood count so the client knows
				// the noise existed and was filtered out.
				inner := truncateResultsKeep(inFam, latest, groupBy, capability, keepBy, unc)
				var ann string
				if strings.Contains(inner, "<isTruncated>") {
					ann = fmt.Sprintf("<scopedTo>%s</scopedTo>\n"+
						"<suppressedUnrelated>%d</suppressedUnrelated>\n", capability, suppressed)
				} else {
					ann = fmt.Sprintf("<isTruncated>true</isTruncated>\n"+
						"<scopedTo>%s</scopedTo>\n"+
						"<suppressedUnrelated>%d</suppressedUnrelated>\n", capability, suppressed)
				}
				return "\n" + ann + strings.TrimPrefix(inner, "\n")
			}
		}
	}
	if len(results) <= effCap {
		// scoping fix: emit the server-side group-by frequency table even when the
		// result fits under the cap (no truncation), BUT only when the caller
		// asked (group_by=) or a capability with a natural grouping dimension is
		// selected. Previously topGroups ran only on the truncation path, so
		// group_by silently produced nothing for sub-64KB streams and the client
		// had to parse raw records to answer "which syscall/op/pid dominates?".
		// The unscoped/ungrouped small-result case is unchanged (legacy output).
		if _, hasKey := capabilityGroupKey[capability]; groupBy != "" || hasKey {
			if tg := markAggregateComplete(topGroupsSummary(results, groupBy, capability)); tg != "" {
				return fmt.Sprintf("\n%s<results>%s</results>\n", tg, results)
			}
			// Fix (review feedback): the caller EXPLICITLY
			// asked group_by=<field> but no aggregate could be built because that
			// field is absent/empty in every record. Do NOT silently return the
			// raw newest records (the client then thinks group_by was ignored);
			// surface a diagnostic naming the requested field and the fields that
			// ARE groupable in this window so it can pick a valid dimension.
			if groupBy != "" {
				avail := groupableFields(results)
				return fmt.Sprintf("\n<groupBy requested=\"%s\" aggregated=\"false\">\n"+
					"  <reason>field %q is not present (or always empty) in the "+
					"captured records, so no frequency table could be built</reason>\n"+
					"  <groupableFields>%s</groupableFields>\n"+
					"</groupBy>\n<results>%s</results>\n",
					groupBy, groupBy, avail, results)
			}
		}
		return fmt.Sprintf("\n<results>%s</results>\n", results)
	}

	// The gadget output buffer is newline-delimited JSON (one event object per
	// line). A naive byte slice at maxResultLen severs the boundary record
	// mid-object, yielding INVALID JSONL: an MCP client that parses the stream
	// (e.g. to reconcile cudaMalloc/cudaFree pairs or count events) then either
	// errors or silently drops a corrupt tail record — and, worse, has NO
	// indication the window was clipped at all. We instead cut on a RECORD
	// (newline) boundary and surface an explicit, machine-readable truncation
	// header: how many complete records were dropped, the total that matched,
	// and an actionable hint to re-run with a tighter filter so the count is a
	// known lower bound rather than a silent one.
	totalRecords := strings.Count(strings.TrimRight(results, "\n"), "\n") + 1

	// scoping fix numeric retention: when keep_by names a numeric field, rank the
	// records by that field DESC and keep the heaviest ones up to the cap. This
	// runs AFTER capability scoping (so in-family rows are the ones ranked) and
	// REPLACES the positional newest/oldest cut for this call. Records missing
	// the field (or non-numeric) sort last so they are dropped first.
	if keepBy != "" {
		if kept, ok := keepTopNByNumeric(results, keepBy, effCap); ok {
			truncated := kept
			totalRecords := strings.Count(strings.TrimRight(results, "\n"), "\n") + 1
			keptRecords := strings.Count(strings.TrimRight(truncated, "\n"), "\n") + 1
			dropped := totalRecords - keptRecords
			if dropped < 0 {
				dropped = 0
			}
			hint := fmt.Sprintf("result clipped to the TOP %d of %d matching "+
				"records by %s (largest first; %d dropped); this is the heavy-"+
				"hitter slice, not the newest — re-run with a tighter filter to "+
				"see more", keptRecords, totalRecords, keepBy, dropped)
			topGroups := markAggregateComplete(topGroupsSummary(results, groupBy, capability))
			inFamilyKept := capabilityInFamilyCount(truncated, capability)
			return fmt.Sprintf("\n<isTruncated>true</isTruncated>\n"+
				"<retention>top-by:%s</retention>\n"+
				"%s"+
				"<totalRecords>%d</totalRecords>\n"+
				"<keptRecords>%d</keptRecords>\n"+
				"<inFamilyRecords>%d</inFamilyRecords>\n"+
				"<droppedRecords>%d</droppedRecords>\n"+
				"<hint>%s</hint>\n"+
				"<results>%s</results>\n",
				keepBy, topGroups, totalRecords, keptRecords, inFamilyKept, dropped, hint, truncated)
		}
		// keepBy not found/numeric in any record -> fall through to positional.
	}

	var truncated string
	if latest {
		// Keep the NEWEST records: advance the cut to the next newline so the
		// retained slice begins at a clean record boundary.
		cut := len(results) - effCap
		if nl := strings.IndexByte(results[cut:], '\n'); nl >= 0 {
			cut = cut + nl + 1
		}
		truncated = results[cut:]
	} else {
		// Keep the OLDEST records: retreat the cut to the previous newline so
		// the retained slice ends at a clean record boundary (no partial tail).
		cut := effCap
		if nl := strings.LastIndexByte(results[:cut], '\n'); nl >= 0 {
			cut = nl + 1
		}
		truncated = results[:cut]
	}

	keptRecords := strings.Count(strings.TrimRight(truncated, "\n"), "\n") + 1
	dropped := totalRecords - keptRecords
	if dropped < 0 {
		dropped = 0
	}

	// Explicit, client-actionable truncation header. The <hint> tells the model
	// the result is a lower bound and how to get a complete view: narrow the
	// query (add a pid/syscall/op filter, or use the capability's *_op selector
	// such as cuda_op=copy / fs_op=open) and re-run, rather than treating the
	// clipped window as the whole story.
	which := "oldest"
	if latest {
		which = "newest"
	}
	hint := fmt.Sprintf("result clipped to the %s %d of %d matching records "+
		"(%d dropped); this count is a LOWER BOUND. For a COMPLETE view do NOT "+
		"parse this clipped sample — either (a) group_by=<dim> for a full-set "+
		"frequency table over ALL %d records (pid/tid/comm resolve through the "+
		"nested proc object; addr/syscall/*_op are top-level); append :<numeric "+
		"field> to SUM that field per group instead of counting (e.g. "+
		"group_by=comm:bytes ranks comms by TOTAL bytes, group_by=pid:duration_ns "+
		"by TOTAL duration -- surfaces a heavy/slow leaker a frequency count "+
		"hides), (b) keep_by=<numeric "+
		"field> to retain the HEAVIEST records by that field over the full set "+
		"instead of the positional %s slice (e.g. keep_by=duration_ns / latency_ns "+
		"surfaces the slow tail even when it falls outside the kept window), or "+
		"(c) re-run with a tighter filter (pid=, syscall=, or a capability *_op= "+
		"selector)", which, keptRecords, totalRecords, dropped, totalRecords, which)

	topGroups := markAggregateComplete(topGroupsSummary(results, groupBy, capability))
	inFamilyKept := capabilityInFamilyCount(truncated, capability)
	return fmt.Sprintf("\n<isTruncated>true</isTruncated>\n"+
		"%s"+
		"<totalRecords>%d</totalRecords>\n"+
		"<keptRecords>%d</keptRecords>\n"+
		"<inFamilyRecords>%d</inFamilyRecords>\n"+
		"<droppedRecords>%d</droppedRecords>\n"+
		"<hint>%s</hint>\n"+
		"<results>%s</results>\n",
		topGroups, totalRecords, keptRecords, inFamilyKept, dropped, hint, truncated)
}

func (g *gadgetManager) getRuntime() (*grpcruntime.Runtime, error) {
	if g.env == "kubernetes" {
		environment.Environment = environment.Kubernetes
		rt := grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
		gp := rt.GlobalParamDescs().ToParams()
		if g.gadgetNamespace != "" {
			if err := gp.Set(grpcruntime.ParamGadgetNamespace, g.gadgetNamespace); err != nil {
				return nil, fmt.Errorf("setting gadget namespace: %w", err)
			}
		}
		if err := rt.Init(gp); err != nil {
			return nil, fmt.Errorf("initializing gadget runtime: %w", err)
		}

		restConfig, err := g.k8sConfig.ToRESTConfig()
		if err != nil {
			return nil, fmt.Errorf("creating REST config: %w", err)
		}
		rt.SetRestConfig(restConfig)

		return rt, nil
	}
	if g.env == "linux" {
		environment.Environment = environment.Local
		rt := grpcruntime.New()
		gp := rt.GlobalParamDescs().ToParams()
		err := gp.Set(grpcruntime.ParamRemoteAddress, g.remoteAddr)
		if err != nil {
			return nil, fmt.Errorf("setting remote address: %w", err)
		}
		if err = rt.Init(gp); err != nil {
			return nil, fmt.Errorf("initializing gadget runtime: %w", err)
		}
		return rt, nil
	}
	return nil, fmt.Errorf("unsupported gadget manager environment: %s", g.env)
}

func (g *gadgetManager) outputOperator(cb func(buf []byte)) operators.DataOperator {
	const opPriority = 50000
	return simple.New("outputOperator",
		simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
			for _, d := range gadgetCtx.GetDataSources() {
				// skip data sources that have the annotation "cli.default-output-mode"
				if m, ok := d.Annotations()["cli.default-output-mode"]; ok && m == "none" {
					continue
				}

				// handle adding a raw string field for certain content types
				restField := d.Annotations()["ebpf.rest.name"]
				var restAcc datasource.FieldAccessor
				var restStrAcc datasource.FieldAccessor
				var err error
				if restField != "" {
					restAcc = d.GetField(restField)
					ct, ok := restAcc.Annotations()["content-type"]
					if ok && ct == "application/x-raw-packet" {
						restStrAcc, err = d.AddField(restField+"_string", api.Kind_String)
						if err != nil {
							return fmt.Errorf("adding raw string field accessor: %w", err)
						}
					}
				}

				jsonFormatter, _ := igjson.New(d,
					igjson.WithShowAll(true),
				)

				d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
					g.formatterMu.Lock()
					defer g.formatterMu.Unlock()
					if restAcc != nil && restStrAcc != nil {
						pktStr := gopacket.NewPacket(restAcc.Get(data), layers.LinkTypeEthernet, gopacket.Default).String()
						err = restStrAcc.Set(data, []byte(pktStr))
						if err != nil {
							return fmt.Errorf("setting raw string field: %w", err)
						}
					}
					jsonData := jsonFormatter.Marshal(data)
					cb(jsonData)
					return nil
				}, opPriority)
			}
			return nil
		}),
	)
}

func gadgetInstanceFromAPI(instance *api.GadgetInstance) *GadgetInstance {
	if instance == nil {
		return nil
	}

	var createdBy string
	for _, tag := range instance.Tags {
		if strings.HasPrefix(tag, "createdBy=") {
			createdBy = strings.TrimPrefix(tag, "createdBy=")
			break
		}
	}

	var params []string
	for k, v := range instance.GadgetConfig.ParamValues {
		if v == "" {
			continue
		}
		params = append(params, fmt.Sprintf("%s=%q", k, v))
	}

	return &GadgetInstance{
		ID:          instance.Id,
		Params:      strings.Join(params, ","),
		GadgetImage: instance.GadgetConfig.ImageName,
		CreatedBy:   createdBy,
		StartedAt:   time.Unix(instance.TimeCreated, 0).Format(time.RFC3339),
	}
}

// keepTopNByNumeric ranks newline-delimited JSON records by the numeric field
// `field` (descending) and returns the largest-valued prefix whose serialized
// size stays within byteCap (maxResultLen by default; LIFTED when the caller
// passed operator.limiter.max-entries=-1 so the heavy-hitter slice is not
// silently re-clipped on top of an already un-limited stream), plus ok=true
// if at least one record carried a
// numeric value for the field. Records lacking the field (or with a
// non-numeric value) sort last and are dropped first. Order within the kept set
// is the ranked order (heaviest first) so the client reads the top contributor
// at the head. Returns ok=false when no record has the field, so the caller can
// fall back to positional truncation.
func keepTopNByNumeric(results, field string, byteCap int) (string, bool) {
	lines := strings.Split(strings.TrimRight(results, "\n"), "\n")
	type rec struct {
		line string
		val  float64
		has  bool
	}
	recs := make([]rec, 0, len(lines))
	any := false
	pat := "\"" + field + "\":"
	for _, ln := range lines {
		r := rec{line: ln}
		if i := strings.Index(ln, pat); i >= 0 {
			j := i + len(pat)
			// skip optional spaces and an opening quote (stringified numbers)
			for j < len(ln) && (ln[j] == ' ' || ln[j] == '"') {
				j++
			}
			k := j
			for k < len(ln) && (ln[k] == '-' || ln[k] == '+' || ln[k] == '.' ||
				ln[k] == 'e' || ln[k] == 'E' || (ln[k] >= '0' && ln[k] <= '9')) {
				k++
			}
			if k > j {
				if v, err := strconv.ParseFloat(ln[j:k], 64); err == nil {
					r.val = v
					r.has = true
					any = true
				}
			}
		}
		recs = append(recs, r)
	}
	if !any {
		return "", false
	}
	// Stable sort: has-field first, then by value desc; ties keep input order.
	sort.SliceStable(recs, func(a, b int) bool {
		if recs[a].has != recs[b].has {
			return recs[a].has
		}
		return recs[a].val > recs[b].val
	})
	var b strings.Builder
	for _, r := range recs {
		if b.Len()+len(r.line)+1 > byteCap {
			break
		}
		b.WriteString(r.line)
		b.WriteByte('\n')
	}
	return b.String(), true
}
