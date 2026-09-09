//go:build linux

package helper

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/tibeahx/OpenRHP/internal/dataplane"
)

func TestLinuxDNSGuardSurvivesNFTFlushAndPreservesOtherUID(t *testing.T) {
	requireNetLab(t)
	if os.Getenv("OPENRHP_DNS_GUARD_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(
			"/usr/bin/unshare",
			"--net",
			binary,
			"-test.run=^TestLinuxDNSGuardSurvivesNFTFlushAndPreservesOtherUID$",
			"-test.v",
		)
		cmd.Env = append(os.Environ(), "OPENRHP_DNS_GUARD_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("namespace: %v\n%s", err, out)
		}
		return
	}
	labCommand(t, "/sbin/ip", "link", "set", "lo", "up")
	labCommand(t, "/sbin/ip", "link", "add", "outside0", "type", "dummy")
	labCommand(t, "/sbin/ip", "link", "set", "outside0", "up")
	labCommand(t, "/sbin/ip", "address", "add", "198.18.0.2/24", "dev", "outside0")
	labCommand(t, "/sbin/ip", "-6", "address", "add", "fd44:2::2/64", "dev", "outside0")
	for _, family := range []string{"-4", "-6"} {
		labCommand(t, "/sbin/ip", family, "route", "add", "default", "dev", "outside0")
	}
	b := labBackend()
	plan := dataplane.Plan{DNSGuardUID: 453}
	if err := b.applyDNSGuard(context.Background(), plan, nil); err != nil {
		t.Fatal(err)
	}
	if err := b.applyDNSGuard(context.Background(), plan, &plan); err != nil {
		t.Fatal("replay", err)
	}
	labCommand(t, "/usr/sbin/nft", "flush", "ruleset")
	for _, family := range []string{"-4", "-6"} {
		target := "8.8.8.8"
		local := "127.0.0.1"
		if family == "-6" {
			target = "2001:4860:4860::8888"
			local = "::1"
		}
		for _, protocol := range []string{"6", "17"} {
			args := []string{
				family,
				"route",
				"get",
				target,
				"uid",
				"453",
				"ipproto",
				protocol,
				"dport",
				"53",
			}
			if out, err := exec.Command("/sbin/ip", args...).CombinedOutput(); err == nil {
				t.Fatalf("DNS owner escaped: %s", out)
			}
			for _, uid := range []string{"0", "454"} {
				args[5] = uid
				labCommand(t, "/sbin/ip", args...)
			}
			args[3] = local
			args[5] = "453"
			labCommand(t, "/sbin/ip", args...)
			args[3] = target
			args[9] = "443"
			labCommand(t, "/sbin/ip", args...)
		}
	}
	// An impostor owner cannot remove the prior account's rule.
	if err := b.removeDNSGuard(context.Background(), dataplane.Plan{DNSGuardUID: 454}); err != nil {
		t.Fatal(err)
	}
	rules, err := b.rules(context.Background(), 4)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, rule := range rules {
		if dnsRuleAllowed(rule, &plan) {
			found++
		}
	}
	if found != 2 {
		t.Fatal("foreign remove altered rules", found)
	}
	if err := b.removeDNSGuard(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	labCommand(
		t,
		"/sbin/ip",
		"-4",
		"route",
		"get",
		"8.8.8.8",
		"uid",
		"453",
		"ipproto",
		"17",
		"dport",
		"53",
	)
}

func TestDNSAccountAndProcessIdentity(t *testing.T) {
	account := "root:x:0:0:root:/root:/bin/ash\ndnsmasq:x:453:453:dns:/var/empty:/bin/false\n"
	uid, gid, err := dnsAccount([]byte(account))
	if err != nil || uid != 453 || gid != 453 {
		t.Fatal(uid, gid, err)
	}
	for _, value := range []string{strings.Replace(account, ":453:453:", ":0:453:", 1), account + "other:x:453:999:other:/tmp:/bin/false\n", account + "other:x:0453:453::/tmp:/bin/false\n", account + "dnsmasq:x:454:454::/tmp:/bin/false\n"} {
		if _, _, err := dnsAccount([]byte(value)); err == nil {
			t.Fatal("unsafe account accepted")
		}
	}
	if _, _, _, err := dnsProcessStatus(
		[]byte("Uid:\t453\t0\t0\t0\nGid:\t453\t453\t453\t453\nPPid:\t1\n"),
	); err == nil {
		t.Fatal("saved/root privilege accepted")
	}
}

func TestOpenWrtDNSIdentityIsolated(t *testing.T) {
	if os.Getenv("OPENRHP_OPENWRT_DNS_LAB") != "1" {
		t.Skip("actual isolated OpenWrt VM only")
	}
	identity, err := inspectDNSIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf(
		"verified dedicated DNS UID=%d GID=%d and trusted executable",
		identity.UID,
		identity.GID,
	)
}

func TestLinuxDNSUnsafeSourceProfiles(t *testing.T) {
	requireNetLab(t)
	dir := t.TempDir()
	cases := []string{
		"#" + strings.Repeat("x", 1023) + "query-port=0\n", "#hidden\x00query-port=0\n",
		"query-port=0\n",
		"query-port=53000\n",
		"server=8.8.8.8@198.18.0.2\n",
		"server=8.8.8.8#5353\n",
		"user=root\n",
		"group=root\n",
		"servers-file=/tmp/arbitrary\n",
		"conf-script=/tmp/arbitrary\n",
	}
	for i, config := range cases {
		included := dir + "/included"
		top := dir + "/top"
		if err := os.WriteFile(included, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			top,
			[]byte("user=dnsmasq\ngroup=dnsmasq\nconf-file="+included+"\n"),
			0o600,
		); err != nil {
			t.Fatal(err)
		}
		if err := checkDNSConfig(top, map[string]bool{}); err == nil {
			t.Fatalf("unsafe nested profile %d accepted", i)
		}
	}
	if err := os.WriteFile(
		dir+"/safe",
		[]byte("user=dnsmasq\ngroup=dnsmasq\nserver=8.8.8.8#53\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := checkDNSConfig(dir+"/safe", map[string]bool{}); err != nil {
		t.Fatal("safe profile", err)
	}
	if err := os.Symlink(dir+"/safe", dir+"/link"); err != nil {
		t.Fatal(err)
	}
	if err := checkDNSConfig(dir+"/link", map[string]bool{}); err == nil {
		t.Fatal("symlink followed")
	}
	include := dir + "/empty"
	if err := os.Mkdir(include, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		dir+"/directory-profile",
		[]byte("conf-dir="+include+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o777, 0o775} {
		if err := os.Chmod(include, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkDNSConfig(dir+"/directory-profile", map[string]bool{}); err == nil {
			t.Fatal("empty writable include directory accepted")
		}
	}
	if err := os.Chmod(include, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(include, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if err := checkDNSConfig(dir+"/directory-profile", map[string]bool{}); err == nil {
		t.Fatal("empty foreign include directory accepted")
	}
	if err := os.Chown(include, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(include, dir+"/directory-alias"); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(dir+"/directory-alias", 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := trustedDNSDirectory(dir + "/directory-alias"); err == nil {
		t.Fatal("untrusted ancestor alias accepted")
	}
}
