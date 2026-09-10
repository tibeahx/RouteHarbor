package helper

import (
	"context"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/model"
)

func TestEmptyIngressBindingSurvivesRestart(t *testing.T) {
	devices := []string{}
	backend := &NetworkBackend{
		Ingress: func(context.Context, model.Network) ([]string, error) { return devices, nil },
	}
	manager := testManager(t, backend, nil)
	desired := testDesired()
	if err := manager.locked(func(s *State) error {
		if err := manager.prepareIngress(context.Background(), s, desired); err != nil {
			return err
		}
		s.Committed = &desired
		return manager.save(s)
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := NewManager(manager.dir, backend, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := restarted.Status()
	if err != nil || !state.IngressBound || len(state.Ingress) != 0 {
		t.Fatal(state, err)
	}
	devices = []string{"new-port"}
	if err := restarted.locked(
		func(s *State) error { return restarted.prepareIngress(context.Background(), s, desired) },
	); err == nil {
		t.Fatal("previously bound empty membership was silently adopted after restart")
	}
}
