package node

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This opt-in integration test exercises upstream UCI, not an emulated parser.
// scripts/lab-uci.sh builds the pinned official implementation in an isolated
// container; no physical router or host network settings are touched.
func TestUCISecretEncodingRoundTripsThroughRealParser(t *testing.T) {
	binary := os.Getenv("ROUTEHARBOR_UCI_TEST_BINARY")
	if binary == "" {
		t.Skip("run scripts/lab-uci.sh to exercise the pinned upstream UCI parser")
	}
	dir := t.TempDir()
	delta := t.TempDir()
	if e := os.WriteFile(
		filepath.Join(dir, "wireless"),
		[]byte("config wifi-iface 'routeharbor_ap'\nconfig wifi-iface 'routeharbor_backhaul'\n"),
		0o600,
	); e != nil {
		t.Fatal(e)
	}
	values := []string{
		"plain-canary-password",
		"quote'canary-key",
		`backslash\canary\key`,
		`double"quote;#$(touch /tmp/never)`,
		"space and ' quote \\ canary",
		`';set wireless.injected=evil;'`,
	}
	for i, value := range values {
		for _, name := range []string{"wireless.routeharbor_ap.key", "wireless.routeharbor_backhaul.key"} {
			cmd := exec.Command(binary, "-c", dir, "-t", delta, "-q", "batch")
			cmd.Stdin = strings.NewReader("set " + name + "=" + uciQuote(value) + "\n")
			output, e := cmd.CombinedOutput()
			if e != nil {
				t.Fatalf("UCI rejected encoded test case %d (output suppressed): %v", i, e)
			}
			if len(bytes.TrimSpace(output)) != 0 {
				t.Fatalf("UCI emitted output for secret assignment in case %d", i)
			}
			if strings.Contains(strings.Join(cmd.Args, " "), value) {
				t.Fatal("test secret entered process argv")
			}
			get := exec.Command(binary, "-c", dir, "-t", delta, "get", name)
			data, e := get.Output()
			if e != nil || string(data) != value+"\n" {
				t.Fatalf("UCI did not preserve secret case %d (values suppressed)", i)
			}
		}
	}
	if data, e := exec.Command(binary, "-c", dir, "-t", delta, "-q", "get", "wireless.injected").
		Output(); e == nil ||
		len(data) != 0 {
		t.Fatal("encoded secret injected an extra UCI section")
	}
	if _, e := os.Stat("/tmp/never"); e == nil {
		t.Fatal("secret metacharacters executed a command")
	}
}
