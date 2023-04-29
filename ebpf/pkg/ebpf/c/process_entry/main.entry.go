/**
*	Type: package
*	Name: entry
*	Description: This package provides the information
*				 of process entry ebpf program.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package entry

import (
	e "tarian/pkg/ebpf"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data entry entry.bpf.c -- -I../../../../headers

/**
*	Type: function
*	Name: GetEbpfObject
*	Description: This function returns the ebpf
*				 information used to load and start it.
*
*	Returns: e.EbofProrgam
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func GetEbpfObject() e.EbpfProgram {
	ep := e.EbpfProgram{}

	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	var bpfObj entryObjects
	err = loadEntryObjects(&bpfObj, nil)
	if err != nil {
		panic(err)
	}

	var event entryEventData
	ep.BpfHook = e.Hook{
		Type:  "tracepoint",
		Group: "syscalls",
		Name:  "sys_enter_execve",
	}
	ep.BpfProgram = bpfObj.ExecveEntry
	ep.BpfMap = bpfObj.Event
	ep.DataType = &event

	return ep
}
