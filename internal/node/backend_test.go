package node

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type recordedCommand struct {
	path  string
	args  []string
	input []byte
}
type uciRunner struct {
	show         map[string]string
	commands     []recordedCommand
	failContains string
}

func (r *uciRunner) Run(
	_ context.Context,
	path string,
	args []string,
	input []byte,
) ([]byte, error) {
	r.commands = append(
		r.commands,
		recordedCommand{path, append([]string(nil), args...), append([]byte(nil), input...)},
	)
	if r.failContains != "" && strings.Contains(strings.Join(args, " "), r.failContains) {
		return nil, errors.New("test command failure")
	}
	if len(args) == 4 && args[0] == "-X" && args[2] == "show" {
		return []byte(r.show[args[3]]), nil
	}
	if len(args) == 2 && args[0] == "export" {
		return []byte("package " + args[1] + "\nconfig test\n"), nil
	}
	return nil, nil
}

func preparedUCI() *uciRunner {
	return &uciRunner{show: map[string]string{
		"network":  "network.home='interface'\nnetwork.home.proto='static'\nnetwork.home.device='br-home'\nnetwork.home.ipaddr='10.0.8.2/24'\nnetwork.homebridge='device'\nnetwork.homebridge.name='br-home'\nnetwork.homebridge.type='bridge'\nnetwork.homebridge.ports='port1' 'port2'\n",
		"dhcp":     "dhcp.home='dhcp'\ndhcp.home.interface='home'\ndhcp.home.ignore='0'\ndhcp.home.ra='server'\n",
		"firewall": "firewall.home='zone'\nfirewall.home.masq='0'\n",
		"wireless": "wireless.radio0='wifi-device'\n",
	}}
}

func TestUCIPlanIsScopedAndDisablesNodeGatewayServices(t *testing.T) {
	runner := preparedUCI()
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	p := plan()
	if e := backend.Apply(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	seen := map[string]bool{}
	for _, command := range runner.commands {
		if strings.Contains(command.path, "sh") {
			t.Fatal("shell executed")
		}
		for _, arg := range command.args {
			seen[arg] = true
			if strings.Contains(arg, "pppoe") || strings.Contains(arg, "network.wan") {
				t.Fatal("unrelated WAN changed")
			}
		}
	}
	for _, required := range []string{"dhcp.home.ignore=1", "dhcp.home.ra=disabled", "dhcp.home.dhcpv6=disabled", "dhcp.home.ndp=disabled", "network.home.gateway=10.0.8.1", "network.homebridge.ports=port1", "network.homebridge.ports=port2"} {
		if !seen[required] {
			t.Errorf("missing required operation: %s", required)
		}
	}
}

func TestNodeServiceRunnerRejectsAnythingOutsideExactReloadOperations(t *testing.T) {
	runner := nodeRunner{}
	for _, command := range []recordedCommand{
		{path: "/etc/init.d/dnsmasq", args: []string{"start"}},
		{path: "/etc/init.d/odhcpd", args: []string{"restart", "extra"}},
		{path: "/sbin/wifi", args: []string{"reload;reboot"}},
		{path: "/sbin/wifi", args: []string{"reload"}, input: []byte("untrusted")},
		{path: "/bin/sh", args: []string{"-c", "true"}},
		{path: "/etc/init.d/unrelated", args: []string{"restart"}},
	} {
		if _, err := runner.Run(
			context.Background(),
			command.path,
			command.args,
			command.input,
		); err == nil ||
			!strings.Contains(err.Error(), "allowlist") {
			t.Fatal("nonallowlisted service operation reached execution")
		}
	}
}

func TestEthernetTransitionRemovesOwnedWirelessUplinkEvenWithoutRadioSettings(t *testing.T) {
	runner := preparedUCI()
	runner.show["wireless"] += "wireless.routeharbor_backhaul='wifi-iface'\nwireless.routeharbor_backhaul.routeharbor_owner='1'\n"
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	if e := backend.Apply(context.Background(), plan()); e != nil {
		t.Fatal(e)
	}
	removed := false
	for _, c := range runner.commands {
		if len(c.args) == 2 && c.args[0] == "delete" &&
			c.args[1] == "wireless.routeharbor_backhaul" {
			removed = true
		}
	}
	if !removed {
		t.Fatal("wireless backhaul retained while Ethernet activated")
	}
}

func TestWirelessTransitionRemovesEthernetUplinkAndSendsCredentialsOnlyOnStdin(t *testing.T) {
	runner := preparedUCI()
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	p := plan()
	p.Mode = "wds"
	p.Uplink = "wlanbackhaul"
	p.EthernetUplink = "port2"
	p.Radio = "radio0"
	p.ShareRadio = true
	p.SSID = "Home $(touch /tmp/never)"
	p.Passphrase = "strong'key;$(not-executed)"
	p.Channel = 6
	if e := backend.Apply(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	seenKey := false
	for _, c := range runner.commands {
		if strings.Contains(strings.Join(c.args, " "), p.Passphrase) {
			t.Fatal("credential exposed in process argv")
		}
		if len(c.args) > 1 && c.args[0] == "add_list" &&
			c.args[1] == "network.homebridge.ports=port2" {
			t.Fatal("Ethernet uplink remained in Wi-Fi bridge")
		}
		if len(c.args) == 2 && c.args[0] == "-q" && c.args[1] == "batch" &&
			string(
				c.input,
			) == "set wireless.routeharbor_backhaul.key="+uciQuote(
				p.Passphrase,
			)+"\n" {
			seenKey = true
		}
	}
	if !seenKey {
		t.Fatal("key was not passed through safely quoted UCI stdin")
	}
}

func TestUCIRejectsForeignObjectsAndCompetingServicesBeforeMutation(t *testing.T) {
	for _, scenario := range []string{"dhcp", "nat", "foreign-radio", "foreign-owned-name", "wrong-address", "port-theft"} {
		t.Run(scenario, func(t *testing.T) {
			runner := preparedUCI()
			p := plan()
			switch scenario {
			case "dhcp":
				runner.show["dhcp"] += "dhcp.guest='dhcp'\ndhcp.guest.interface='guest'\n"
			case "nat":
				runner.show["firewall"] += "firewall.wan.masq='1'\n"
			case "foreign-radio":
				p.Radio = "radio0"
				p.SSID = "Home"
				p.Passphrase = "example-password"
				p.Channel = 6
				runner.show["wireless"] += "wireless.existing='wifi-iface'\nwireless.existing.device='radio0'\n"
			case "foreign-owned-name":
				runner.show["wireless"] += "wireless.routeharbor_backhaul='wifi-iface'\n"
			case "wrong-address":
				p.ManagementAddress = "10.0.8.5/24"
			case "port-theft":
				p.LANPorts = append(p.LANPorts, "wanport")
			}
			backend := &UCIBackend{
				Runner:       runner,
				Capabilities: func(context.Context) Capabilities { return caps() },
			}
			if e := backend.Apply(context.Background(), p); e == nil {
				t.Fatal("unsafe adoption accepted")
			}
			for _, c := range runner.commands {
				if len(c.args) > 0 &&
					(c.args[0] == "set" || c.args[0] == "delete" || c.args[0] == "commit" || c.args[0] == "add_list") {
					t.Fatal("mutation preceded preflight rejection")
				}
			}
		})
	}
}

func TestSnapshotIsValidatedBeforeAnyRestoreMutation(t *testing.T) {
	runner := preparedUCI()
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	snapshot, e := backend.Snapshot(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	snapshot["firewall"] = nil
	runner.commands = nil
	if e = backend.Restore(context.Background(), snapshot, plan()); e == nil {
		t.Fatal("broken snapshot accepted")
	}
	if len(runner.commands) != 0 {
		t.Fatal("partial snapshot imported before validating the entire rollback")
	}
}

type serviceUCI struct {
	*uciRunner
	missing string
}

func (r serviceUCI) Available(path string) error {
	if path == r.missing {
		return errors.New("unavailable")
	}
	return nil
}

func TestMissingServiceToolsFailBeforeMutationAndEthernetDoesNotReloadWiFi(t *testing.T) {
	for _, missing := range []string{"/etc/init.d/dnsmasq", "/etc/init.d/odhcpd", "/sbin/wifi"} {
		runner := serviceUCI{uciRunner: preparedUCI(), missing: missing}
		backend := &UCIBackend{
			Runner:       runner,
			Capabilities: func(context.Context) Capabilities { return caps() },
		}
		p := plan()
		if missing == "/sbin/wifi" {
			p.Radio, p.SSID, p.Passphrase, p.Channel = "radio0", "Home", "private-key", 6
		}
		if err := backend.Apply(
			context.Background(),
			p,
		); err == nil ||
			!strings.Contains(err.Error(), "missing") {
			t.Fatal("missing service prerequisite was not reported")
		}
		for _, c := range runner.commands {
			if len(c.args) > 0 &&
				(c.args[0] == "set" || c.args[0] == "delete" || c.args[0] == "commit") {
				t.Fatal("network mutation preceded missing-tool rejection")
			}
		}
	}
	runner := serviceUCI{uciRunner: preparedUCI(), missing: "/sbin/wifi"}
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	if err := backend.Apply(context.Background(), plan()); err != nil {
		t.Fatal("Ethernet without radio changes incorrectly requires wifi:", err)
	}
	snapshot, err := backend.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	snapshot["wireless"] = []byte("package wireless\nconfig wifi-device 'radio0'\n")
	if err := backend.Restore(context.Background(), snapshot, plan()); err != nil {
		t.Fatal(err)
	}
	for _, c := range runner.commands {
		if c.path == "/sbin/wifi" {
			t.Fatal("Ethernet apply or rollback reloaded an unchanged radio")
		}
	}
}

func TestSetupDiscoveryExposesDetectedChoicesWithoutWiFiKeys(t *testing.T) {
	runner := preparedUCI()
	runner.show["network"] += "network.home.gateway='10.0.8.1'\n"
	runner.show["wireless"] += "wireless.radio0.channel='6'\nwireless.foreign='wifi-iface'\nwireless.foreign.device='radio0'\nwireless.foreign.key='PRIVATE-KEY-NEVER-EXPORT'\n"
	backend := &UCIBackend{
		Runner:       runner,
		Capabilities: func(context.Context) Capabilities { return caps() },
	}
	setup, err := backend.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(setup.Bridges) != 1 || setup.Bridges[0].Interface != "home" ||
		setup.Bridges[0].Gateway != "10.0.8.1" ||
		len(setup.Bridges[0].Ports) != 2 {
		t.Fatalf("missing discovered setup: %+v", setup)
	}
	if len(setup.Radios) != 1 || !setup.Radios[0].ForeignActive || setup.Radios[0].Channel != 6 {
		t.Fatalf("radio conflict not detected: %+v", setup)
	}
	encoded, _ := json.Marshal(setup)
	if strings.Contains(string(encoded), "PRIVATE-KEY") {
		t.Fatal("setup discovery leaked Wi-Fi key")
	}
}

func TestWirelessAdvertisementDoesNotCertifyPeerCompatibility(t *testing.T) {
	evidence := ParseWirelessEvidence(
		[]byte(
			"Wiphy phy0\n\tSupported interface modes:\n\t\t * managed\n\t\t * AP\n\t\t * mesh point\n",
		),
	)
	if len(evidence) != 1 || len(evidence[0].AdvertisedModes) != 3 || evidence[0].PeerVerified {
		t.Fatalf("driver modes were confused with verified interoperability: %+v", evidence)
	}
}
