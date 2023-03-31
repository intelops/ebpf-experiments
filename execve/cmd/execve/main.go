package main

import (
	"C"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)
import (
	"bytes"
	"encoding/binary"
)

//Ebpf map item structure
type event_data struct {
	Pid        uint32
	Tgid       uint32
	Uid        uint32
	Gid        uint32
	Syscall_nr int32
	Comm       [80]uint8
	Filename   [256]uint8
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS bpf index.bpf.c -- -I../../headers

func main() {
	//Removes memory lock limit of the ebpf program
	err := rlimit.RemoveMemlock()
	must("Error while removing the memlock", err)

	//Loads ebpf objects(programs, maps)
	ebpfColl := bpfObjects{}
	err = loadBpfObjects(&ebpfColl, nil)
	must("Error while loading the ebpf object", err)

	//Attach program to a hook
	hook, err := link.Tracepoint("syscalls", "sys_enter_execve", ebpfColl.EbpfExecve, nil)
	must("Error while attaching a ebpf program", err)
	defer hook.Close()

	//Create perf map reader
	perfReader, err := perf.NewReader(ebpfColl.Event, 4096)
	must("Error while creating map reader", err)
	defer perfReader.Close()

	//reads data from map
	mapDataEmitter := make(chan perf.Record)
	go func() {
		defer close(mapDataEmitter)

		for {
			record, err := perfReader.Read()
			must("Error while reading map", err)

			mapDataEmitter <- record
		}

	}()

	//parses map data and prints to screen
	prompt("Waiting for event to trigger!")
	for {
		record := <-mapDataEmitter

		var row event_data
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &row)
		must("Error while parsing the data", err)

		printToScreen(row)
		prompt("Waiting for event to trigger!")
	}
}

func must(msg string, err error) {
	if err != nil {
		fmt.Printf("%s : %v", msg, err)
	}
}

func printToScreen(row event_data) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("Process Id: %d\n", row.Pid)
	fmt.Printf("Thread Id: %d\n", row.Tgid)
	fmt.Printf("User Id: %d\n", row.Uid)
	fmt.Printf("Group Id: %d\n", row.Gid)
	fmt.Printf("Syscall Number: %d\n", row.Syscall_nr)
	fmt.Printf("Command: %s\n", row.Comm)
	fmt.Printf("Filename: %s\n", row.Filename)
	fmt.Println("-----------------------------------------")
}

func prompt(msg string) {
	fmt.Printf("\n %s \r", msg)
}
