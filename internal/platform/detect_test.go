package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner func(context.Context, string, []string, []byte) ([]byte, error)

func (f fakeRunner) Run(c context.Context, b string, a []string, i []byte) ([]byte, error) {
	return f(c, b, a, i)
}

func TestNetifdUsesRolesNotConventionalNames(t *testing.T) {
	data := []byte(
		`{"interface":[{"interface":"family","l3_device":"switch3","proto":"static","up":true,"ipv4-address":[{"address":"10.44.0.1","mask":24}]},{"interface":"fiber","l3_device":"pppoe-fiber","proto":"pppoe","up":true,"route":[{"target":"0.0.0.0","mask":0}]}]}`,
	)
	got, e := ParseInterfaces(data)
	if e != nil {
		t.Fatal(e)
	}
	if len(got) != 2 || got[0].Device != "switch3" || got[0].Role != "local" ||
		got[1].Role != "uplink" {
		t.Fatalf("wrong roles %+v", got)
	}
}

func TestNonLinuxNeverRunsCommands(t *testing.T) {
	d := Detector{
		OS: "darwin",
		Runner: fakeRunner(func(context.Context, string, []string, []byte) ([]byte, error) {
			t.Fatal("host network command")
			return nil, nil
		}),
	}
	r := d.Detect(context.Background())
	if r.Supported || len(r.Issues) == 0 {
		t.Fatal(r)
	}
}

func TestFw3IsExplicitlyRejected(t *testing.T) {
	d := Detector{OS: "linux", ReadFile: func(p string) ([]byte, error) {
		if p == "/etc/openwrt_release" {
			return []byte("DISTRIB_RELEASE='24.10.0'\nDISTRIB_ARCH='mipsel_24kc'"), nil
		}
		return nil, errors.New("missing")
	}, Exists: func(p string) bool { return p == "/sbin/procd" }, Runner: fakeRunner(func(context.Context, string, []string, []byte) ([]byte, error) {
		return []byte(`{"interface":[]}`), nil
	})}
	r := d.Detect(context.Background())
	if r.Supported {
		t.Fatal("fw3 not implemented")
	}
	if !strings.Contains(strings.Join(r.Issues, " "), "fw4") {
		t.Fatal(r)
	}
}

func TestShellReleaseNotExecuted(t *testing.T) {
	r := parseRelease("DISTRIB_RELEASE='$(touch /tmp/not-executed)'\nexport DISTRIB_ARCH=x")
	if r["DISTRIB_RELEASE"] != "$(touch /tmp/not-executed)" || r["DISTRIB_ARCH"] != "" {
		t.Fatal(r)
	}
}

func TestUBusUsesFixedOpenWrtLocations(t *testing.T) {
	for _, installed := range []string{"/bin/ubus", "/sbin/ubus"} {
		got := ubusBinary(func(path string) bool { return path == installed })
		if got != installed || !binaries[got] {
			t.Fatalf("ubus location %s resolved to %s", installed, got)
		}
	}
}
