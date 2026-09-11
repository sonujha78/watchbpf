package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/sonujha78/watchbpf/internal/baseline"
	"github.com/sonujha78/watchbpf/internal/llm"
	"github.com/sonujha78/watchbpf/internal/policy"
	"github.com/sonujha78/watchbpf/internal/enforce"
	"github.com/sonujha78/watchbpf/internal/embedded"
	"github.com/sonujha78/watchbpf/internal/audit"
	"github.com/sonujha78/watchbpf/internal/config"
	"github.com/sonujha78/watchbpf/internal/metrics"
	"strings"
)

type execEvent struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
	Args     [4][64]byte
}
type openEvent struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}
type connectEvent struct {
	Pid     uint32
	Uid     uint32
	Comm    [16]byte
	DstAddr uint32
	DstPort uint16
}

type probeConfig struct {
	objBytes   []byte
	progName   string
	mapName    string
	tpCategory string
	tpName     string
	eventLabel string
}

var (
	auditLogger *audit.Logger
	llmSemaphore = make(chan struct{}, 3) // max 3 concurrent LLM calls
	escalationCount int
	escalationMu     sync.Mutex
	escalationWindow = time.Now()
	selfPID    = uint32(os.Getpid())
	excludedComms = map[string]bool{
		"ollama":       true,
		"llama-server": true,
		"watchbpf-agent": true,
	}
	mode       = flag.String("mode", "learn", "learn | filter")
	statePath  = flag.String("state", "baseline.json", "path to baseline allowlist file")
	promptPath = flag.String("prompt", "prompts/v1.txt", "path to LLM prompt template")
	configPath = flag.String("config", "/etc/watchbpf/config.yaml", "path to YAML config file (optional)")
	metricsAddr = flag.String("metrics-addr", ":9090", "address for Prometheus /metrics endpoint")
	cfg        *config.Config
	store      *baseline.Store
	llmClient  llm.Client
	policyEngine *policy.Engine
	enforceMode  = flag.String("enforce", "dry-run", "dry-run | live")
)

func main() {
	flag.Parse()

	var cfgErr error
	cfg, cfgErr = config.Load(*configPath)
	if cfgErr != nil {
		log.Fatalf("loading config: %v", cfgErr)
	}

	if *mode != "learn" && *mode != "filter" {
		log.Fatalf("invalid -mode %q: must be 'learn' or 'filter'", *mode)
	}

	store = baseline.NewStore(*statePath)
	log.Printf("Baseline store loaded: %d known entries (mode=%s)", store.Count(), *mode)

	// LLM client select karo — Gemini pehle try karo (agar key hai), warna Ollama
	if *mode == "filter" {
		promptTemplate := embedded.PromptV1

		if gc := llm.NewGeminiClient(promptTemplate); gc != nil {
			llmClient = gc
			log.Printf("LLM backend: %s (BYOK key detected)", gc.Name())
		} else {
			oc := llm.NewOllamaClient(promptTemplate)
			llmClient = oc
			log.Printf("LLM backend: %s (no Gemini key found, using local fallback)", oc.Name())
		}
	}

	policyEngine = policy.NewEngine(*enforceMode, cfg.ProtectedProcesses, cfg.RateLimit.MaxPerMinute, cfg.Thresholds.Alert, cfg.Thresholds.Soft, cfg.Thresholds.Hard)

	metrics.StartServer(*metricsAddr)
	log.Printf("Policy engine initialized (enforce=%s, thresholds=%d/%d/%d, rate_limit=%d/min, protected=%d procs)", *enforceMode, cfg.Thresholds.Alert, cfg.Thresholds.Soft, cfg.Thresholds.Hard, cfg.RateLimit.MaxPerMinute, len(cfg.ProtectedProcesses))

	var err2 error
	auditLogger, err2 = audit.NewLogger("/var/log/watchbpf-audit.log")
	if err2 != nil {
		log.Printf("WARNING: audit logger init failed: %v (continuing without audit log)", err2)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing memlock limit:", err)
	}

	probes := []probeConfig{
		{embedded.ExecveObj, "handle_execve", "rb", "syscalls", "sys_enter_execve", "EXEC"},
		{embedded.OpenatObj, "handle_openat", "rb_open", "syscalls", "sys_enter_openat", "OPEN"},
		{embedded.ConnectObj, "handle_connect", "rb_connect", "syscalls", "sys_enter_connect", "CONNECT"},
	}

	var wg sync.WaitGroup
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	saveTicker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-saveTicker.C:
				store.Save()
			case <-stopper:
				saveTicker.Stop()
				store.Save()
				return
			}
		}
	}()

	fmt.Printf("WatchBPF Phase 3 — mode=%s. Press Ctrl+C to stop.\n", *mode)
	fmt.Println("TAG\t\tTYPE\t\tPID\tUID\tCOMM\t\tDETAIL")

	for _, p := range probes {
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(p.objBytes))
		if err != nil {
			log.Fatalf("[%s] loading spec: %v", p.eventLabel, err)
		}
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Fatalf("[%s] loading collection: %v", p.eventLabel, err)
		}
		defer coll.Close()

		prog := coll.Programs[p.progName]
		m := coll.Maps[p.mapName]
		if prog == nil || m == nil {
			log.Fatalf("[%s] program or map missing", p.eventLabel)
		}

		tp, err := link.Tracepoint(p.tpCategory, p.tpName, prog, nil)
		if err != nil {
			log.Fatalf("[%s] attaching tracepoint: %v", p.eventLabel, err)
		}
		defer tp.Close()

		rd, err := ringbuf.NewReader(m)
		if err != nil {
			log.Fatalf("[%s] opening ringbuf reader: %v", p.eventLabel, err)
		}
		defer rd.Close()

		go func() {
			<-stopper
			rd.Close()
		}()

		wg.Add(1)
		label := p.eventLabel
		go func() {
			defer wg.Done()
			readLoop(label, rd)
		}()
	}

	wg.Wait()
	fmt.Println("\nAll readers stopped. Exiting.")
}

func readLoop(label string, rd *ringbuf.Reader) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[%s] reading ringbuf: %v", label, err)
			continue
		}

		buf := bytes.NewBuffer(record.RawSample)
		var comm, detail string
		var pid, uid uint32

		switch label {
		case "EXEC":
			var ev execEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			filename := cstr(ev.Filename[:])
			comm, pid, uid = cstr(ev.Comm[:]), ev.Pid, ev.Uid

			var argParts []string
			for _, slot := range ev.Args {
				a := cstr(slot[:])
				if a != "" {
					argParts = append(argParts, a)
				}
			}
			if len(argParts) > 0 {
				detail = filename + " " + strings.Join(argParts, " ")
			} else {
				detail = filename
			}

		case "OPEN":
			var ev openEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			comm, detail, pid, uid = cstr(ev.Comm[:]), cstr(ev.Filename[:]), ev.Pid, ev.Uid

		case "CONNECT":
			var ev connectEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, ev.DstAddr)
			comm, detail, pid, uid = cstr(ev.Comm[:]), fmt.Sprintf("%s:%d", ip.String(), ev.DstPort), ev.Pid, ev.Uid
		}

		metrics.EventsProcessed.WithLabelValues(label).Inc()
		handleEvent(label, comm, detail, pid, uid)
	}
}

func handleEvent(eventType, comm, detail string, pid, uid uint32) {
	// Self-feedback-loop guard: apna khud ka process aur Ollama/llama-server
	// ke traffic ko kabhi LLM tak escalate mat karo
	if pid == selfPID || excludedComms[comm] {
		return
	}

	known := store.IsKnown(eventType, comm, detail)

	if *mode == "learn" {
		if !known {
			store.Learn(eventType, comm, detail)
			fmt.Printf("[LEARNED]\t%s\t\t%s\t\t%s\n", eventType, comm, detail)
		}
		return
	}

	// mode == "filter"
	if known {
		return
	}

	metrics.EventsEscalated.WithLabelValues(eventType).Inc()
	fmt.Printf("[ESCALATE]\t%s\t\t%s\t\t%s\n", eventType, comm, detail)

	// Rate-limit guard: agar 1 minute mein 50 se zyada escalations ho jaayein,
	// to LLM ko spam karna band kar do (event-storm protection)
	escalationMu.Lock()
	if time.Since(escalationWindow) > time.Minute {
		escalationCount = 0
		escalationWindow = time.Now()
	}
	escalationCount++
	overLimit := escalationCount > 50
	escalationMu.Unlock()

	if overLimit {
		metrics.EventsRateLimited.Inc()
		fmt.Printf("[RATE-LIMITED]\tescalation storm detected — skipping LLM call for this event\n")
		if auditLogger != nil {
			auditLogger.Log(eventType, comm, detail, pid, -1, "rate_limited", "escalation storm — LLM call skipped", "")
		}
		return
	}

	if llmClient == nil {
		return
	}

	// IMPORTANT: LLM call ko goroutine mein bhejo, taaki ring buffer reader
	// kabhi block na ho — warna slow LLM response ke dauran naye kernel events
	// silently drop ho jaate hain (ring buffer full ho jaata hai)
	go func() {
		llmSemaphore <- struct{}{}        // slot lo
		defer func() { <-llmSemaphore }() // slot chhodo
		processLLM(eventType, comm, detail, pid, uid)
	}()
}

func processLLM(eventType, comm, detail string, pid, uid uint32) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	story := llm.EventStory{EventType: eventType, Comm: comm, Detail: detail, PID: pid, UID: uid}
	assessment, err := llmClient.Assess(ctx, story)
	if err != nil {
		metrics.LLMCalls.WithLabelValues(llmClient.Name(), "error").Inc()
		log.Printf("[LLM-ERROR] %v — falling back to log-only", err)
		return
	}
	metrics.LLMCalls.WithLabelValues(llmClient.Name(), "success").Inc()

	fmt.Printf("[AI-VERDICT]\tscore=%d\tlabel=%s\ttactic=%s\taction=%s\treason=%q\n",
		assessment.ThreatScore, assessment.Label, assessment.MitreTactic, assessment.Action, assessment.Rationale)

	decision := policyEngine.Evaluate(comm, assessment.ThreatScore)
	metrics.Decisions.WithLabelValues(string(decision.Tier)).Inc()
	fmt.Printf("[DECISION]\ttier=%s\treason=%q\n", decision.Tier, decision.Reason)

	if auditLogger != nil {
		if err := auditLogger.Log(eventType, comm, detail, pid, assessment.ThreatScore, string(decision.Tier), decision.Reason, ""); err != nil {
			log.Printf("WARNING: audit log write failed: %v", err)
		}
	}

	// Sirf tab actual action lo jab decision truly hard/soft ho (dry-run reason string check karke)
	isDryRun := strings.HasPrefix(decision.Reason, "DRY-RUN")

	switch decision.Tier {
	case policy.TierHard:
		if isDryRun {
			fmt.Printf("[ACTION]\twould KILL pid=%d (comm=%s) — dry-run, no action taken\n", pid, comm)
		} else {
			if err := enforce.KillProcess(pid); err != nil {
				log.Printf("[ACTION-ERROR] kill failed: %v", err)
			} else {
				fmt.Printf("[ACTION]\tKILLED pid=%d (comm=%s)\n", pid, comm)
			}
			if eventType == "CONNECT" {
				ip := strings.Split(detail, ":")[0]
				if err := enforce.IsolateIP(ip); err != nil {
					log.Printf("[ACTION-ERROR] isolate failed: %v", err)
				} else {
					fmt.Printf("[ACTION]\tISOLATED ip=%s\n", ip)
				}
			}
		}
	case policy.TierSoft:
		if isDryRun {
			fmt.Printf("[ACTION]\twould PAUSE pid=%d (comm=%s) — dry-run, no action taken\n", pid, comm)
		} else {
			if err := enforce.PauseProcess(pid); err != nil {
				log.Printf("[ACTION-ERROR] pause failed: %v", err)
			} else {
				fmt.Printf("[ACTION]\tPAUSED pid=%d (comm=%s)\n", pid, comm)
			}
		}
	}
}

func cstr(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		idx = len(b)
	}
	return string(b[:idx])
}
