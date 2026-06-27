package gadgetmanager

import (
	"strings"
	"testing"
)

// TestTopGroups_BlockIOKeysOnDev proves the spec-named 'dev' natural field is
// honoured: selecting capability=block_io keys the topGroups summary on the
// device (dev_t major:minor) -- the block-device saturation dimension -- not on
// req_op and not hijacked by the always-on fs_trace 'fname' flood. This closes
// the 'dev -> MISSING' capabilityGroupKey gap (review feedback).
func TestTopGroups_BlockIOKeysOnDev(t *testing.T) {
	// Mixed stream: real mep_blk rows (carry dev + req_op) interleaved with the
	// always-on fs_trace flood (carry fname). dev 271581185 == 0x10300001 etc.
	var b strings.Builder
	for i := 0; i < 8; i++ {
		b.WriteString(`{"dev":271581185,"sector":1000,"req_op":1,"latency_ns":40000}` + "\n")
	}
	for i := 0; i < 5; i++ {
		b.WriteString(`{"dev":271581186,"sector":2000,"req_op":0,"latency_ns":15000}` + "\n")
	}
	// fs flood that would hijack the key to fname if scoping were broken:
	for i := 0; i < 50; i++ {
		b.WriteString(`{"fname":"/var/log/x","fs_op":"read","comm":"rsyslogd"}` + "\n")
	}
	got := topGroupsSummary(b.String(), "", "block_io")

	if !strings.Contains(got, `key="dev"`) {
		t.Fatalf("block_io must key topGroups on the spec-named device field 'dev'; got: %q", got)
	}
	if strings.Contains(got, `key="fname"`) {
		t.Fatalf("block_io topGroups must NOT be hijacked by the fs_trace 'fname' flood; got: %q", got)
	}
	if strings.Contains(got, `key="req_op"`) {
		t.Fatalf("block_io natural key is 'dev' (device saturation), not 'req_op'; got: %q", got)
	}
	// the busier device (271581185, 8 I/Os) must rank above the quieter one.
	idxBusy := strings.Index(got, "271581185")
	idxQuiet := strings.Index(got, "271581186")
	if idxBusy < 0 || idxQuiet < 0 || idxBusy > idxQuiet {
		t.Fatalf("busier device 271581185(8) should rank before 271581186(5); got: %q", got)
	}
	t.Logf("block_io keys on dev, ranks busiest device first: %q", got)
}
