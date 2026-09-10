package helper

import (
	"encoding/json"
	"testing"

	"github.com/tibeahx/RouteHarbor/internal/adapter"
	"github.com/tibeahx/RouteHarbor/internal/model"
)

func TestManagedEngineRequestRejectsPrivilegesImportsAndUnpinnedEndpoints(t *testing.T) {
	source := model.Source{
		ID:       "a",
		Name:     "A",
		Type:     "sing-box",
		Enabled:  true,
		Settings: json.RawMessage(`{"type":"http","server":"1.1.1.1","server_port":8080}`),
	}
	path := adapter.AllocatePath(source.ID, source.Type, 1)
	path.UDP = false
	path.ProxyPort = 12001
	path.TransparentPort = 12002
	valid := EngineRequest{Source: source, Path: path}
	if e := ValidateEngineRequest(valid); e != nil {
		t.Fatal(e)
	}
	for _, change := range []func(*EngineRequest){func(r *EngineRequest) { r.Path.Mark = 0 }, func(r *EngineRequest) { r.Path.ProxyPort = 22 }, func(r *EngineRequest) { r.Path.ProxyPort = r.Path.TransparentPort }, func(r *EngineRequest) { r.Path.Interface = "eth0" }, func(r *EngineRequest) { r.Path.UDP = true }, func(r *EngineRequest) { r.Path.SourceID = "other" }, func(r *EngineRequest) {
		r.Source.Settings = json.RawMessage(`{"type":"http","server":"proxy.example","server_port":8080}`)
	}, func(r *EngineRequest) { r.Path.DNSPort = 12003; r.DNSResolver = "127.0.0.1" }} {
		r := valid
		change(&r)
		if e := ValidateEngineRequest(r); e == nil {
			t.Fatal("unsafe managed engine request accepted", r.Path)
		}
	}
	var request Request
	if e := DecodeStrict([]byte(`{"operation":"start_engine","uid":0}`), &request); e == nil {
		t.Fatal("caller-controlled UID accepted")
	}
	if e := validateRequest(Request{Operation: "status", Engine: &valid}); e == nil {
		t.Fatal("engine payload on unrelated operation accepted")
	}
}
