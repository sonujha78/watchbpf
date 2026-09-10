package main

import (
	"bytes"
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
)

type execEvent struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
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
	objPath    string
	progName   string
	mapName    string
	tpCategory string
	tpName     string
	eventLabel string
}

var (
	mode      = flag.String("mode", "learn", "learn | filter")
	statePath = flag.String("state", "baseline.json", "path to baseline allowlist file")
	store     *baseline.Store
)

func main() {
	flag.Parse()

	if *mode != "learn" && *mode != "filter" {
		log.Fatalf("invalid -mode %q: must be 'learn' or 'filter'", *mode)
	}

	store = baseline.NewStore(*statePath)
	log.Printf("Baseline store loaded: %d known entries (mode=%s)", store.Count(), *mode)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing memlock limit:", err)
	}

	probes := []probeConfig{
		{"bpf/execve.bpf.o", "handle_execve", "rb", "syscalls", "sys_enter_execve", "EXEC"},
		{"bpf/openat.bpf.o", "handle_openat", "rb_open", "syscalls", "sys_enter_openat", "OPEN"},
		{"bpf/connect.bpf.o", "handle_connect", "rb_connect", "syscalls", "sys_enter_connect", "CONNECT"},
	}

	var wg sync.WaitGroup
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)

	// Har 30 second mein allowlist disk pe save karo (learning mode ke liye)
	saveTicker := time.NewTicker(30 * time.Second)
	go func() {
		for {
			select {
			case <-saveTicker.C:
				if err := store.Save(); err != nil {
					log.Printf("error saving baseline: %v", err)
				}
			case <-stopper:
				saveTicker.Stop()
				store.Save()
				return
			}
		}
	}()

	fmt.Printf("WatchBPF Phase 2 — mode=%s. Press Ctrl+C to stop.\n", *mode)
	fmt.Println("TAG\t\tTYPE\t\tPID\tUID\tCOMM\t\tDETAIL")

	for _, p := range probes {
		spec, err := ebpf.LoadCollectionSpec(p.objPath)
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

		switch label {
		case "EXEC":
			var ev execEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			comm = cstr(ev.Comm[:])
			detail = cstr(ev.Filename[:])

		case "OPEN":
			var ev openEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			comm = cstr(ev.Comm[:])
			detail = cstr(ev.Filename[:])

		case "CONNECT":
			var ev connectEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, ev.DstAddr)
			comm = cstr(ev.Comm[:])
			detail = fmt.Sprintf("%s:%d", ip.String(), ev.DstPort)
		}

		handleEvent(label, comm, detail)
	}
}

// handleEvent baseline filter logic apply karta hai
func handleEvent(eventType, comm, detail string) {
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
		return // baseline mein hai — silently allow, print mat karo
	}
	fmt.Printf("[ESCALATE]\t%s\t\t%s\t\t%s\n", eventType, comm, detail)
}

func cstr(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		idx = len(b)
	}
	return string(b[:idx])
}
