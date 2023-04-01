
package main

import (
	//"fmt"
	"log"
	"net"
	"os"
	//"strings"
	//"time"

	//"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)
//The ebpf package provides access to eBPF functionality, and the link package provides access to network interface management functionality.
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_pass.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	//Look up the network interface by name.
	//function starts by checking that a network interface name was specified as a command-line argument. 
	//It then looks up the interface by name using the net.InterfaceByName function.
		
		ifaceName := os.Args[1]
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			log.Fatalf("lookup network iface %q: %s", ifaceName, err)
		}
		
// Load pre-compiled programs into the kernel using loadBpfObjects function

objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
	log.Fatalf("loading objects: %s", err)
}
defer objs.Close()

//AttachXDP links an XDP BPF program to an XDP hook.
//
l, err := link.AttachXDP(link.XDPOptions{
	Program:   objs.XdpProgFunc,
	Interface: iface.Index,
})
if err != nil {
	log.Fatalf("could not attach XDP program: %s", err)
}
defer l.Close()

log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
log.Printf("Press Ctrl-C to exit and remove the program")


}
