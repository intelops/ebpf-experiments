
package main

import (
	//"fmt"
	"log"
	//"net"
	//"os"
	//"strings"
	//"time"

	//"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_pass.c -- -I../headers

func main() {
// Load pre-compiled programs into the kernel using loadBpfObjects function
objs := bpfObjects{}
if err := loadBpfObjects(&objs, nil); err != nil {
	log.Fatalf("loading objects: %s", err)
}
defer objs.Close()

l, err := link.AttachXDP(link.XDPOptions{
	Program:   objs.XdpProgFunc,
//	Interface: iface.Index,
})
if err != nil {
	log.Fatalf("could not attach XDP program: %s", err)
}
defer l.Close()

log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
log.Printf("Press Ctrl-C to exit and remove the program")


}