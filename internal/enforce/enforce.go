package enforce

import (
	"fmt"
	"os/exec"
	"syscall"
)

// KillProcess ek PID ko SIGKILL bhejta hai — hard action ke liye
func KillProcess(pid uint32) error {
	if pid == 0 || pid == 1 {
		return fmt.Errorf("refusing to kill PID %d (init/invalid)", pid)
	}
	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("SIGKILL failed for pid %d: %w", pid, err)
	}
	return nil
}

// PauseProcess ek PID ko SIGSTOP bhejta hai — soft action ke liye (reversible, kill nahi karta)
func PauseProcess(pid uint32) error {
	if pid == 0 || pid == 1 {
		return fmt.Errorf("refusing to pause PID %d (init/invalid)", pid)
	}
	if err := syscall.Kill(int(pid), syscall.SIGSTOP); err != nil {
		return fmt.Errorf("SIGSTOP failed for pid %d: %w", pid, err)
	}
	return nil
}

// ResumeProcess ek paused process ko wapas chalu karta hai (SIGCONT)
func ResumeProcess(pid uint32) error {
	if err := syscall.Kill(int(pid), syscall.SIGCONT); err != nil {
		return fmt.Errorf("SIGCONT failed for pid %d: %w", pid, err)
	}
	return nil
}

// IsolateIP nftables ke through ek destination IP ko block/drop kar deta hai
// (naya "watchbpf-block" chain use karta hai, taaki main firewall rules disturb na ho)
func IsolateIP(ip string) error {
	// Chain exist karo pehle (agar already hai to error ignore, harmless)
	exec.Command("nft", "add", "chain", "inet", "filter", "watchbpf_block",
		"{", "type", "filter", "hook", "output", "priority", "0", ";", "}").Run()

	cmd := exec.Command("nft", "add", "rule", "inet", "filter", "watchbpf_block",
		"ip", "daddr", ip, "drop")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables isolate failed for %s: %w (output: %s)", ip, err, string(out))
	}
	return nil
}
