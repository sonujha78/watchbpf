package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// event struct MUST exactly match the C struct in execve.bpf.c (same field order, same sizes)
type event struct {
	Pid      uint32
	Uid      uint32
	Comm     [16]byte
	Filename [256]byte
}

func main() {
	// Purane kernels ke liye memlock limit hatao (kernel 7.0 mein zaroori nahi, but safe practice hai)
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("removing memlock limit:", err)
	}

	// Compiled eBPF object file load karo
	spec, err := ebpf.LoadCollectionSpec("bpf/execve.bpf.o")
	if err != nil {
		log.Fatalf("loading collection spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Fatalf("loading BPF collection into kernel: %v", err)
	}
	defer coll.Close()

	prog := coll.Programs["handle_execve"]
	if prog == nil {
		log.Fatal("program 'handle_execve' not found in collection")
	}

	rbMap := coll.Maps["rb"]
	if rbMap == nil {
		log.Fatal("map 'rb' not found in collection")
	}

	// Program ko tracepoint pe attach karo — ab kernel actually events bhejna shuru karega
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
	if err != nil {
		log.Fatalf("attaching tracepoint: %v", err)
	}
	defer tp.Close()

	// Ring buffer reader banao
	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Ctrl+C pe gracefully close karne ke liye
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt)
	go func() {
		<-stopper
		rd.Close()
	}()

	fmt.Println("WatchBPF Phase 1 — watching execve() syscalls. Press Ctrl+C to stop.")
	fmt.Println("PID\tUID\tCOMM\t\tFILENAME")

	var ev event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("\nReceived signal, exiting...")
				return
			}
			log.Printf("reading from ringbuf: %v", err)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("parsing ringbuf event: %v", err)
			continue
		}

		comm := unixCString(ev.Comm[:])
		filename := unixCString(ev.Filename[:])
		fmt.Printf("%d\t%d\t%s\t\t%s\n", ev.Pid, ev.Uid, comm, filename)
	}
}

// unixCString null-terminated byte array ko Go string mein convert karta hai
func unixCString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		idx = len(b)
	}
	return string(b[:idx])
}
