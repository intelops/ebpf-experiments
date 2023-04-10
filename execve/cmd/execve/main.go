//Author: Charan Ravela
//Start Date: 03-20-2023
//Last Updated: 04-06-2023

package main

import (
	"C"
	"fmt"
)
import (
	"bytes"
	"encoding/binary"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data bpf index.bpf.c -- -I../../headers

func main() {
	//Removes memory lock limit of the ebpf program
	err := rlimit.RemoveMemlock()
	must("Error while removing the memlock", err, true)

	//Loads ebpf objects(programs, maps)
	ebpfColl := bpfObjects{}
	err = loadBpfObjects(&ebpfColl, nil)
	must("Error while loading the ebpf object", err, true)
	defer ebpfColl.Close()

	//Attach program to a hook
	hook, err := link.Tracepoint("syscalls", "sys_enter_execve", ebpfColl.EbpfExecve, nil)
	must("Error while attaching a ebpf program", err, true)
	defer hook.Close()

	//Create ringbuffer map reader
	ringbufReader, err := ringbuf.NewReader(ebpfColl.Event)
	must("Error while creating map reader", err, true)
	defer ringbufReader.Close()

	//reads data from map
	mapDataEmitter := make(chan ringbuf.Record)
	go func() {
		defer close(mapDataEmitter)

		for {
			record, err := ringbufReader.Read()
			must("Error while reading map", err, true)

			mapDataEmitter <- record
		}

	}()

	//parses map data and prints to screen
	prompt("Waiting for event to trigger!")
	for {
		record := <-mapDataEmitter

		var row bpfEventData
		err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &row)
		must("Error while parsing the data", err, true)

		printToScreen(row)
		prompt("Waiting for event to trigger!")
	}
}

func must(msg string, err error, shouldTerminte bool) {
	if err != nil {
		fmt.Printf("\n%s : %v\n", msg, err)
		if shouldTerminte {
			os.Exit(1)
		}
	}
}

func printToScreen(row bpfEventData) {
	fmt.Println("-----------------------------------------")
	fmt.Printf("User Id: %d\n", row.Uid)
	fmt.Printf("Group Id: %d\n", row.Gid)
	fmt.Printf("Command: %s\n", row.Comm)
	fmt.Printf("Syscall Number: %d\n", row.SyscallNr)
	fmt.Printf("Process Id: %d\n", row.Pid)
	fmt.Printf("Thread Group Id: %d\n", row.Tgid)
	fmt.Printf("Current Working Directory: %s\n", sanitizeText(string(row.Cwd[:])))
	fmt.Printf("Binary Filepath: %s\n", sanitizeText(string(row.BinaryFilepath[:])))
	fmt.Printf("User Command: %v\n", sanitizeUserCommand(row.UserComm))
	fmt.Println("-----------------------------------------")
}

func prompt(msg string) {
	fmt.Printf("\n%s \r", msg)
}

//removes the null characters from the end of string
func sanitizeText(str string) (restr string) {
	strb := []byte(str)
	restr = string(bytes.Split(strb[:], []byte("\x00"))[0])

	return
}

//removes the null characters from array elements
//and removes the empty array elements
func sanitizeUserCommand(tdarr [256][256]uint8) []string {
	var comms []string

	for _, ele := range tdarr {
		str := sanitizeText(string(ele[:]))
		if len(str) != 0 {
			comms = append(comms, str)
		}
	}

	return comms
}
