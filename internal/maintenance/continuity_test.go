package maintenance

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestContinuityPackageAdmissionAndControllerRemoval(t *testing.T) {
	request := Request{
		Action:     "install",
		BundleID:   strings.Repeat("a", 32),
		Components: []string{"openrhp-continuity"},
	}
	if err := ValidateRequest(request, false); err != nil {
		t.Fatal(err)
	}
	payload := packageBytes(
		t,
		"openrhp-continuity",
		"0.1.0-r1",
		[]member{{"usr/libexec/openrhp-continuity", []byte("worker"), 0, ""}},
	)
	if metadata, err := InspectIPK(
		bytes.NewReader(payload),
	); err != nil ||
		metadata.Name != "openrhp-continuity" {
		t.Fatal("continuity package rejected", err)
	}
	if configurationPayload("usr/libexec/openrhp-continuity", []string{"usr/libexec"}) {
		t.Fatal("critical continuity executable can bypass payload verification as conffile")
	}
	if !recoverablePackage("openrhp-continuity") {
		t.Fatal("continuity package cannot participate in offline recovery")
	}
	backend := &fakeBackend{
		packages: map[string]string{
			"openrhp":            "0.1.0-r1",
			"openrhp-guard":      "0.1.0-r1",
			"openrhp-continuity": "0.1.0-r1",
		},
	}
	plan, err := makePlan(
		context.Background(),
		backend,
		Request{
			Action:        "remove",
			Components:    []string{"openrhp"},
			RemovalPolicy: "preserve-closed",
		},
		bundleRecord{},
	)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, p := range plan.Packages {
		names[p.Name] = true
	}
	if !names["openrhp-continuity"] || names["openrhp-guard"] || len(names) != 2 {
		t.Fatal("controller removal loses continuity dependency or guard boundary", names)
	}
}
