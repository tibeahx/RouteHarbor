//go:build linux

package helper

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestLinuxPacketManagerCrashChild(t *testing.T) {
	if os.Getenv("ROUTEHARBOR_PACKET_CRASH_CHILD") != "1" {
		t.Skip("subprocess only")
	}
	requireNetLab(t)
	cmd, life, err := startPacketWorker(73)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = life.Close() }()
	defer func() { _ = cmd.Wait() }()
	if err = os.WriteFile(
		os.Getenv("ROUTEHARBOR_PACKET_WORKER_PID"),
		[]byte(strconv.Itoa(cmd.Process.Pid)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestLinuxPacketSupervisorAfterManagerSIGKILL(t *testing.T) {
	requireNetLab(t)
	pidFile := filepath.Join(t.TempDir(), "worker.pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestLinuxPacketManagerCrashChild$", "-test.v")
	parent.Env = append(
		os.Environ(),
		"ROUTEHARBOR_PACKET_CRASH_CHILD=1",
		"ROUTEHARBOR_PACKET_WORKER_PID="+pidFile,
	)
	parent.Stdout = os.Stderr
	parent.Stderr = os.Stderr
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = parent.Process.Kill(); _ = parent.Wait() }()
	deadline := time.Now().Add(8 * time.Second)
	workerPID, nfqPID := "", ""
	lastChildren := ""
	for time.Now().Before(deadline) {
		data, _ := os.ReadFile(pidFile)
		workerPID = strings.TrimSpace(string(data))
		if _, err := strconv.Atoi(workerPID); err == nil {
			lastChildren = ""
			tasks, _ := filepath.Glob("/proc/" + workerPID + "/task/*/children")
			for _, task := range tasks {
				children, _ := os.ReadFile(task)
				lastChildren += " " + string(children)
			}
			for _, pid := range strings.Fields(lastChildren) {
				args, _ := os.ReadFile("/proc/" + pid + "/cmdline")
				status, _ := os.ReadFile("/proc/" + pid + "/status")
				if strings.Contains(string(args), "--qnum=21073") &&
					strings.Contains(string(status), "Uid:\t65534\t65534\t65534\t65534") {
					nfqPID = pid
				}
			}
		}
		if nfqPID != "" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if nfqPID == "" {
		for _, pid := range strings.Fields(lastChildren) {
			args, _ := os.ReadFile("/proc/" + pid + "/cmdline")
			status, _ := os.ReadFile("/proc/" + pid + "/status")
			t.Logf("worker child %s argv %q status %s", pid, args, status)
		}
		t.Fatalf(
			"supervised nfqws did not start and drop privileges: worker %s children %s",
			workerPID,
			lastChildren,
		)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	deadline = time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat("/proc/" + nfqPID); os.IsNotExist(err) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("nfqws survived manager SIGKILL; liveness supervisor failed to kill and reap it")
}

func TestPacketWorkerRequiresValidSlotAndPrivatePipe(t *testing.T) {
	if _, _, err := startPacketWorker(0); err == nil {
		t.Fatal("invalid worker slot accepted")
	}
	if _, _, err := startPacketWorker(251); err == nil {
		t.Fatal("invalid worker slot accepted")
	}
	if err := RunPacketWorker(-1); err == nil {
		t.Fatal("invalid worker slot accepted")
	}
}

func TestPacketReadinessRequiresTheExactQueueOwner(t *testing.T) {
	raw := []byte("21073 123 0 2 65531 0 0 0 1\n21074 124 0 2 65531 0 0 0 1\n")
	if !packetQueueOwned(raw, 21073, 123) {
		t.Fatal("own bound source queue not recognized")
	}
	if packetQueueOwned(raw, 21073, 124) || packetQueueOwned(raw, 21075, 123) ||
		packetQueueOwned([]byte("21073 123"), 21073, 123) {
		t.Fatal("foreign or incomplete queue data reported ready")
	}
}
