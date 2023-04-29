/**
*	Type: package
*	Name: exit
*	Description: This package provides the information
*				 of process exit ebpf program.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package exit

import (
	e "tarian/pkg/ebpf"

	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data exit exit.bpf.c -- -I../../../../headers

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

	var bpfObj exitObjects
	err = loadExitObjects(&bpfObj, nil)
	if err != nil {
		panic(err)
	}

	var event exitEventData
	ep.BpfHook = e.Hook{
		Type:  "tracepoint",
		Group: "syscalls",
		Name:  "sys_exit_execve",
	}
	ep.BpfProgram = bpfObj.ExecveExit
	ep.BpfMap = bpfObj.Event
	ep.DataType = &event

	return ep
}
