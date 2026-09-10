package helper

import (
	"strings"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/dispatch"
)

func TestContinuityBridgeTypedValidation(t *testing.T) {
	r := continuityFixture(t)
	r.Bridge = &dispatch.Bridge{
		Port:     14501,
		Username: strings.Repeat("ab", 16),
		Password: strings.Repeat("cd", 32),
	}
	if e := ValidateContinuityWorker(r); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*dispatch.Bridge){func(b *dispatch.Bridge) { b.Port = 80 }, func(b *dispatch.Bridge) { b.Port = 14500 }, func(b *dispatch.Bridge) { b.Username = "short" }, func(b *dispatch.Bridge) { b.Password = strings.Repeat("!", 64) }} {
		b := *r.Bridge
		change(&b)
		bad := r
		bad.Bridge = &b
		if e := ValidateContinuityWorker(bad); e == nil {
			t.Fatal("invalid bridge accepted")
		}
	}
}
