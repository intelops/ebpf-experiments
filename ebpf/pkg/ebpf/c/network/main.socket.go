package network

import (
	"C"
	e "tarian/pkg/ebpf"

	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event bpf socket.c -- -I../../../../headers

func GetEbpfObject() e.EbpfProgram {
	ep := e.EbpfProgram{}

	err := rlimit.RemoveMemlock()
	if err != nil {
		panic(err)
	}

	var bpfObj bpfObjects
	err = loadBpfObjects(&bpfObj, nil)
	if err != nil {
		panic(err)
	}

	var event bpfEvent
	ep.BpfHook = e.Hook{
		Type: "kprobe",
		Name: "__x64_sys_socket",
	}
	ep.BpfProgram = bpfObj.X64SysSocket
	ep.BpfMap = bpfObj.Events
	ep.DataType = &event

	return ep
}
