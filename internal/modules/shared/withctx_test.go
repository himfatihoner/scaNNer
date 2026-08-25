package shared

import (
	"context"
	"net/http"
	"testing"
)

// Regression: a transport registered through a WithCtx-derived copy must land in
// the scan-registered parent's pool, so scanmgr's CloseIdleConnections(parent)
// flushes it on finish instead of leaking it until GC (advancedweb Stage 10).
func TestWithCtxFunnelsTransports(t *testing.T) {
	parent := &HTTPOptions{}
	cp := parent.WithCtx(context.Background())
	tr := &http.Transport{}
	cp.RegisterTransport(tr)

	if len(cp.transports) != 0 {
		t.Fatalf("derived copy kept its own transport (%d); should funnel to parent", len(cp.transports))
	}
	if len(parent.transports) != 1 || parent.transports[0] != tr {
		t.Fatalf("transport did not land in parent's pool: %d entries", len(parent.transports))
	}

	// Chained WithCtx must still funnel to the ultimate root.
	cp2 := cp.WithCtx(context.Background())
	tr2 := &http.Transport{}
	cp2.RegisterTransport(tr2)
	if len(parent.transports) != 2 {
		t.Fatalf("chained WithCtx did not funnel to root: parent has %d", len(parent.transports))
	}
}
