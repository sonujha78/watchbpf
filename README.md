# WatchBPF

**Real-time Linux kernel threat detection & automated remediation, powered by eBPF + LLM reasoning.**

WatchBPF traces critical syscalls at the kernel level using eBPF/CO-RE, filters out normal behavior with a self-learning baseline, and sends only genuinely novel or suspicious activity to an LLM (your own free Gemini API key, or a local Ollama model) for contextual threat scoring. Based on that score, a tiered policy engine can alert, isolate, or terminate the offending process — with safety-first defaults throughout.

Single static binary. No vendor lock-in. Bring your own key, or run fully offline.

> **Status:** Core engine (kernel tracing → baseline filter → AI scoring → policy-based enforcement) complete and tested. Packaging for public release in progress.

---

## Why WatchBPF?

Most open eBPF security tools stop at detection: they fire an alert and leave triage and response to you. Enterprise tools that close that loop (Tetragon, CrowdStrike, Datadog) are heavy, closed, or expensive. WatchBPF is built to close the gap for solo developers, homelab/K8s tinkerers, and small teams who want more than raw `auditd` logs but can't justify an enterprise contract.

| | Falco | Tetragon | **WatchBPF** |
|---|:---:|:---:|:---:|
| eBPF kernel-level tracing | ✅ | ✅ | ✅ |
| AI-based contextual threat scoring | ❌ | ❌ | ✅ (Gemini / Ollama) |
| Autonomous remediation | ❌ Alerts only | ✅ Policy-based | ✅ LLM-informed + policy-based |
| Free, zero mandatory API cost | ✅ | ✅ | ✅ (BYOK, or fully offline via Ollama) |
| Single static binary | ❌ | ❌ | ✅ |
| Beginner-friendly install | ❌ | ❌ | ✅ One-command install |

WatchBPF isn't claiming to be the first eBPF security tool — it combines AI-driven reasoning with real enforcement in a package anyone can install and run for free.

---

## How It Works

```
Kernel syscalls (execve, openat, connect, ...)
        │  eBPF/CO-RE probes, near-zero overhead
        ▼
Baseline filter  ──── learns normal behavior, drops known-good events
        │  only novel/ambiguous events pass through
        ▼
AI diagnosis engine  ──── Gemini (BYOK) or local Ollama
        │  returns: threat_score, MITRE tactic, confidence, rationale
        ▼
Policy engine  ──── tiered thresholds, dry-run by default
        │
        ▼
Enforcement  ──── alert / cgroup freeze / SIGKILL / nftables isolation
        │
        ▼
Immutable, hash-chained audit log
```

1. **eBPF probes** trace `execve`, `openat`, and `connect` (and more) at the kernel level with near-zero overhead.
2. A **baseline/allowlist filter** learns normal system behavior during an initial learning window, so only genuinely novel events get escalated — this is what keeps LLM usage (and cost) low.
3. Escalated events are packaged into a compact "event story" and sent to an **LLM** — your own Gemini API key, or a local Ollama model as a free, fully offline fallback — which returns a structured threat score, MITRE ATT&CK tactic, and recommended action.
4. A **policy engine** applies tiered, configurable thresholds with safety guardrails: dry-run mode by default, a protected-process list, and rate-limited actions to prevent runaway responses.
5. When enabled, the **enforcement module** can freeze, kill, or isolate malicious processes via cgroups and nftables.
6. Every decision is written to an **append-only, hash-chained audit log** for forensics and review.

---

## Quick Start

### Requirements

- Linux kernel 5.15+ with BTF support (`/sys/kernel/btf/vmlinux` must exist)
- x86_64 (arm64 support planned)

### Install

```bash
git clone https://github.com/sonujha78/watchbpf.git
cd watchbpf
bash deploy/install.sh
```

### Run (dry-run mode, safe by default)

```bash
sudo systemctl start watchbpf
sudo journalctl -u watchbpf -f
```

WatchBPF starts in **dry-run mode**: it observes and logs what it *would* do, without taking any action. Review its behavior on your system for a while before enabling live enforcement.

### Add your own LLM backend (optional)

WatchBPF works out of the box via a local Ollama model — no cost, fully offline. To use Gemini's free tier instead:

```bash
sudo nano /etc/watchbpf/gemini.key
# paste your free Gemini API key from https://aistudio.google.com/app/apikey
sudo chmod 600 /etc/watchbpf/gemini.key
sudo systemctl restart watchbpf
```

### Enable live enforcement (only after reviewing dry-run behavior)

Edit `/etc/systemd/system/watchbpf.service` and change `-enforce=dry-run` to `-enforce=live`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl restart watchbpf
```

---

## Safety Guardrails

WatchBPF can terminate processes and firewall IPs — that capability is treated as non-negotiable to guard carefully:

- **Dry-run by default** — no destructive action until you explicitly enable live enforcement.
- **Protected-process list** — critical system processes (`sshd`, `systemd`, `kubelet`, containerd, WatchBPF itself, etc.) can never be hard-killed.
- **Rate-limited actions** — caps kills/isolations per minute, so a single bad LLM response can't cascade into taking down the whole box.
- **Strict output validation** — the LLM's recommended action is checked against a fixed enum server-side; malformed or off-schema responses are always treated as log-only, never acted on.
- **Prompt-injection resistant** — process names/args are attacker-controlled input; they're sanitized and the model is explicitly instructed to treat them as data, not instructions.
- **Fail-safe on API failure** — if Gemini/Ollama is unreachable, WatchBPF falls back to local rule-based heuristics rather than failing open or silently.
- **Kill-switch** — a single config flag/env var disables all auto-action instantly.

---

## Configuration

All thresholds, allowlists, and the enforcement mode live in a hot-reloadable YAML config (`/etc/watchbpf/config.yaml`). Default response tiers:

| Threat Score | Action |
|---|---|
| 0–39 | Log only |
| 40–69 | Alert (webhook/Slack) + flag for review |
| 70–89 | Soft action — cgroup freeze / rate-limit the process |
| 90–100 | Hard action — SIGKILL + nftables IP quarantine |

All thresholds are overridable in config.

---

## Architecture

See [docs/architecture.md](docs/architecture.md) *(coming soon)* for the full data-flow diagram and component breakdown.

## Observability

WatchBPF exposes a Prometheus `/metrics` endpoint (events/sec, LLM latency, action counts) with an included Grafana dashboard JSON.

## Roadmap

- [ ] Docker image
- [ ] Helm chart / K8s DaemonSet polish
- [ ] arm64 support
- [ ] Public launch

## License

Apache License 2.0

## Contributing

Contributions welcome — see `CONTRIBUTING.md` *(coming soon)*. Issues and PRs will be open once the repo goes public.
