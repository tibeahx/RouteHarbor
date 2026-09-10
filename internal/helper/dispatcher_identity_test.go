package helper

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const (
	identityAddressFixture = `[{"ifindex":7,"ifname":"wan0","flags":["UP","LOWER_UP"],"operstate":"UP","addr_info":[{"family":"inet","local":"192.168.7.2","prefixlen":24,"scope":"global"},{"family":"inet6","local":"2001:db8::2","prefixlen":64,"scope":"global"}]}]`
	identityRoute4Fixture  = `[{"dst":"default","gateway":"192.168.7.1","dev":"wan0","metric":10,"protocol":"dhcp","expires":55}]`
	identityRoute6Fixture  = `[{"dst":"default","gateway":"fe80::1","dev":"wan0","metric":20,"expires":90}]`
)

func TestDispatcherWANIdentityChangesActualDHCPAddressGatewayLinkAndMetric(t *testing.T) {
	hash := func(a, b, c string) string {
		t.Helper()
		v, err := hashDispatcherWANIdentity("wan0", []byte(a), []byte(b), []byte(c))
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	initial := hash(identityAddressFixture, identityRoute4Fixture, identityRoute6Fixture)
	if len(initial) != 64 || strings.Contains(initial, "192.168") {
		t.Fatal("identity must be an opaque digest", initial)
	}
	for name, fixtures := range map[string][3]string{
		"address-within-same-subnet": {strings.Replace(identityAddressFixture, "192.168.7.2", "192.168.7.3", 1), identityRoute4Fixture, identityRoute6Fixture},
		"ipv6-address":               {strings.Replace(identityAddressFixture, "2001:db8::2", "2001:db8::3", 1), identityRoute4Fixture, identityRoute6Fixture},
		"ifindex-recreated":          {strings.Replace(identityAddressFixture, `"ifindex":7`, `"ifindex":8`, 1), identityRoute4Fixture, identityRoute6Fixture},
		"v4-gateway":                 {identityAddressFixture, strings.Replace(identityRoute4Fixture, "192.168.7.1", "192.168.7.254", 1), identityRoute6Fixture},
		"v6-gateway":                 {identityAddressFixture, identityRoute4Fixture, strings.Replace(identityRoute6Fixture, "fe80::1", "fe80::2", 1)},
		"metric":                     {identityAddressFixture, strings.Replace(identityRoute4Fixture, `"metric":10`, `"metric":11`, 1), identityRoute6Fixture},
	} {
		t.Run(name, func(t *testing.T) {
			if got := hash(fixtures[0], fixtures[1], fixtures[2]); got == initial {
				t.Fatal("changed WAN retained identity")
			}
		})
	}
	if got := hash(
		identityAddressFixture,
		strings.Replace(identityRoute4Fixture, `"expires":55`, `"expires":54`, 1),
		identityRoute6Fixture,
	); got != initial {
		t.Fatal("expiry countdown creates a false WAN change")
	}
	if got := hash(
		strings.Replace(identityAddressFixture, `["UP","LOWER_UP"]`, `["LOWER_UP","UP"]`, 1),
		identityRoute4Fixture,
		identityRoute6Fixture,
	); got != initial {
		t.Fatal("irrelevant flag ordering changed identity")
	}
}

func TestDispatcherWANIdentityUnknownStateAndMalformedOutputStayUnknown(t *testing.T) {
	for _, a := range []string{"null", `[]`, `not-json`, identityAddressFixture + ` {}`, strings.Replace(identityAddressFixture, `"ifname":"wan0"`, `"ifname":"other0"`, 1), strings.Replace(identityAddressFixture, `"operstate":"UP"`, `"operstate":"DOWN"`, 1), strings.Replace(identityAddressFixture, `"local":"192.168.7.2"`, `"local":"PRIVATE-DATA-CANARY"`, 1), strings.Repeat("x", maxWANIdentityBytes+1)} {
		if value, err := hashDispatcherWANIdentity(
			"wan0",
			[]byte(a),
			[]byte(identityRoute4Fixture),
			[]byte(identityRoute6Fixture),
		); err == nil || value != "" ||
			err.Error() != "wan_identity_unavailable" {
			t.Fatal("unknown identity accepted or diagnostics leaked", value, err)
		}
	}
	if _, err := hashDispatcherWANIdentity(
		"wan0",
		[]byte(identityAddressFixture),
		[]byte(`[]`),
		[]byte(`[]`),
	); err == nil {
		t.Fatal("absence of default route accepted")
	}
}

type identityRecordingRunner struct {
	args    [][]string
	failure bool
}

func (r *identityRecordingRunner) Run(
	_ context.Context,
	binary string,
	args []string,
	input []byte,
) ([]byte, error) {
	if binary != "/sbin/ip" || input != nil {
		return nil, errors.New("unexpected command")
	}
	r.args = append(r.args, args)
	if r.failure {
		return nil, errors.New("SECRET raw network output")
	}
	switch len(r.args) {
	case 1:
		return []byte(identityAddressFixture), nil
	case 2:
		return []byte(identityRoute4Fixture), nil
	default:
		return []byte(identityRoute6Fixture), nil
	}
}

func TestDispatcherWANIdentityUsesOnlyFixedReadCommands(t *testing.T) {
	runner := &identityRecordingRunner{}
	if _, err := inspectDispatcherWANIdentity(context.Background(), runner, "wan0"); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-j", "address", "show", "dev", "wan0"},
		{"-4", "-j", "route", "show", "table", "main", "default", "dev", "wan0"},
		{"-6", "-j", "route", "show", "table", "main", "default", "dev", "wan0"},
	}
	if !reflect.DeepEqual(runner.args, want) {
		t.Fatal("commands escaped fixed read allowlist", runner.args)
	}
	bad := &identityRecordingRunner{failure: true}
	if _, err := inspectDispatcherWANIdentity(
		context.Background(),
		bad,
		"wan0",
	); err == nil ||
		strings.Contains(err.Error(), "SECRET") {
		t.Fatal("command output exposed", err)
	}
	invalid := &identityRecordingRunner{}
	if _, err := inspectDispatcherWANIdentity(
		context.Background(),
		invalid,
		"wan0;id",
	); err == nil ||
		len(invalid.args) != 0 {
		t.Fatal("unvalidated interface executed")
	}
}
