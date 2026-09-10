package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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

// probeConfig ek object file, uske program/map naam, aur tracepoint ko bundle karta hai
type probeConfig struct {
	objPath     string
	progName    string
	mapName     string
	tpCategory  string
	tpName      string
	eventLabel  string
}

func main() {
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

	fmt.Println("WatchBPF Phase 2 — watching execve / openat / connect. Press Ctrl+C to stop.")
	fmt.Println("TYPE\t\tPID\tUID\tCOMM\t\tDETAIL")

	for _, p := range probes {
		spec, err := ebpf.LoadCollectionSpec(p.objPath)
		if err != nil {
			log.Fatalf("[%s] loading spec: %v", p.eventLabel, err)
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Fatalf("[%s] loading collection into kernel: %v", p.eventLabel, err)
		}
		defer coll.Close()

		prog := coll.Programs[p.progName]
		if prog == nil {
			log.Fatalf("[%s] program %q not found", p.eventLabel, p.progName)
		}

		m := coll.Maps[p.mapName]
		if m == nil {
			log.Fatalf("[%s] map %q not found", p.eventLabel, p.mapName)
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

		switch label {
		case "EXEC":
			var ev execEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			fmt.Printf("%s\t\t%d\t%d\t%s\t\t%s\n", label, ev.Pid, ev.Uid, cstr(ev.Comm[:]), cstr(ev.Filename[:]))

		case "OPEN":
			var ev openEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			fmt.Printf("%s\t\t%d\t%d\t%s\t\t%s\n", label, ev.Pid, ev.Uid, cstr(ev.Comm[:]), cstr(ev.Filename[:]))

		case "CONNECT":
			var ev connectEvent
			if err := binary.Read(buf, binary.LittleEndian, &ev); err != nil {
				continue
			}
			ip := make(net.IP, 4)
			binary.LittleEndian.PutUint32(ip, ev.DstAddr)
			fmt.Printf("%s\t%d\t%d\t%s\t\t%s:%d\n", label, ev.Pid, ev.Uid, cstr(ev.Comm[:]), ip.String(), ev.DstPort)
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
