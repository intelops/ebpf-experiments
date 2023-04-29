/**
*	Type: package
*	Name: network
*	Description: This package provides the information
*				 of process exit ebpf program.
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package network

import (
	"C"

	e "tarian/pkg/ebpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags $BPF_CFLAGS -type event_data network network.bpf.c -- -I../../../../headers

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
*	Created On: 04-27-2023
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

	var bpfObj networkObjects
	err = loadNetworkObjects(&bpfObj, nil)
	if err != nil {
		panic(err)
	}

	var event networkEventData
	ep.BpfHook = e.Hook{
		Type: "xdp",
		XdpOpts: link.XDPOptions{
			Program:   bpfObj.XdpProgFunc,
			Interface: 1,
		},
	}
	ep.BpfProgram = bpfObj.XdpProgFunc
	ep.BpfMap = bpfObj.Event
	ep.DataType = &event

	return ep
}
