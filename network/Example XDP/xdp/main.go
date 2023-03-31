// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.

package main //package main is the entry point of a Go program 

//import is used to include packages in a Go program.These packages provide functions and types that the program can use to accomplish its desired functionality.

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//The ebpf package provides access to eBPF functionality, and the link package provides access to network interface management functionality.


// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp.c -- -I../headers

//Go directive to generate Go code from the C code in xdp.c
//The bpf2go tool is used to generate the Go code, and the generated code will be saved in a bpf package.

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

// Look up the network interface by name.
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

///XDP program is attached to the specified interface using the AttachXDP function.
//The objs.XdpProgFunc parameter specifies the function that represents the eBPF program.
//iface.Index specifies the index of the network interface.
	
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

// Print the contents of the BPF LRU hash map to stdout every second using the formatMapContents function.(source IP address -> packet count).
//The time.NewTicker function is used to create a ticker that triggers every second


	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.XdpStatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

// formatMapContents function formats the contents of the map into a string.
func formatMapContents(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key []byte
		val uint32
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sourceIP := net.IP(key) // IPv4 source address in network byte order.
		packetCount := val
		sb.WriteString(fmt.Sprintf("\t%s => %d\n", sourceIP, packetCount))
	}
	return sb.String(), iter.Err()
}
