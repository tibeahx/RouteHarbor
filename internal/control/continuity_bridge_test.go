package control

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/helper"
)

func TestContinuityBridgeReservationPrivateCopyAndRedactedStatus(t *testing.T) {
	b, l, e := reserveContinuityBridge()
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = l.Close() }()
	if len(b.Username) != 32 || len(b.Password) != 64 {
		t.Fatal("wrong credential entropy")
	}
	if _, e = hex.DecodeString(b.Password); e != nil {
		t.Fatal(e)
	}
	if occupied, e := net.Listen("tcp4", l.Addr().String()); e == nil {
		_ = occupied.Close()
		t.Fatal("bridge reservation not held")
	}
	cc := &ContinuityControl{request: &helper.ContinuityWorkerRequest{Bridge: b}}
	copy := cc.Bridge()
	copy.Password = "changed"
	if cc.Bridge().Password != b.Password {
		t.Fatal("private alias escaped")
	}
	public, e := json.Marshal(cc.Public())
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(public), b.Username) ||
		strings.Contains(string(public), b.Password) ||
		strings.Contains(string(public), "bridge") {
		t.Fatal("bridge leaked in public status")
	}
}
