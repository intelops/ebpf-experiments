package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"time"
	"fmt"
	"C"
	"strconv"
	"strings"
	"net"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

)


// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf network_call.c -- -I../headers

// main starts the x64_sys_socket kernel. It is called by kprobe and execve
func main() {

	
	// Name of the kernel function to trace.
	ebpf_accept := "__x64_sys_accept"
	ebpf_bind := "__x64_sys_bind"
	ebpf_connect := "__x64_sys_connect"
	ebpf_listen := "__x64_sys_listen"
	ebpf_socket := "__x64_sys_socket"
	// Allow the current process to lock memory for eBPF resources.
	// Remove the memlock from the rlimit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	// Load the BPF objects from the BPF file.
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	Accept, err := link.Kprobe(ebpf_accept, objs.X64SysAccept, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer Accept.Close()


	Bind, err := link.Kprobe(ebpf_bind, objs.X64SysBind, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer Bind.Close()

// will emit an event containing pid and command of the execved task.
	Connect, err := link.Kprobe(ebpf_connect, objs.X64SysConnect, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer Connect.Close()

	Listen, err := link.Kprobe(ebpf_listen, objs.X64SysListen, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer Listen.Close()

	Socket, err := link.Kprobe(ebpf_socket, objs.X64SysSocket, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer Socket.Close()


	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C{
		formatmap_accept(objs.ArgsMapAccept)
		formatmap_bind(objs.ArgsMapBind)
		formatmap_connect(objs.ArgsMapConnect)
		formatmap_listen(objs.ArgsMapListen)
		formatmap_socket(objs.ArgsMapSocket)
		
	}
}


func formatmap_socket(m *ebpf.Map) (error) {
	var(
		
		key uint32
		val []byte// can we read a buffer here 
	)

	iter := m.Iterate()
	for iter.Next(&key,&val){
		eventid := key
		buffer := val

		fmt.Println("-----------------------------------------")
		Domain, err := getIntegerValue(buffer[:8])
		if err != nil {
			fmt.Println("Error:", err)
		}
		//getSocketDomain(Domain)
		fmt.Printf("\t Thread Id(socket) %d => Socket domain: %s\n ",eventid,getSocketDomain(Domain))

		socket_type, err := getIntegerValue(buffer[8:16])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id(socket) %d => Socket type: %s\n",eventid,getSocketType(socket_type))

		
		//get protocol
		protocol, err := getIntegerValue(buffer[16:24])
		if err != nil {
			fmt.Println("Error:", err)
		}
		protocolInt32 := int32(protocol)

		fmt.Printf("\t Thread Id(socket) %d => Socket protocol: %s\n",eventid,getProtocol(protocolInt32))
		fmt.Println("-----------------------------------------")
	}
	
	return iter.Err()
}

func formatmap_connect(m *ebpf.Map) (error) {
	var(
		key uint32
		val []byte// can we read a buffer here 
	)

	iter := m.Iterate()
	for iter.Next(&key,&val){
		eventid := key
		buffer := val
		
		fmt.Println("-----------------------------------------")
		fd, err := getIntegerValue(buffer[:8])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id(connect) %d => connect Socket fd: %d\n ",eventid,fd)
		
		
		addr, err := getIntegerValue(buffer[8:16])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id(connect) %d => connect addrress : %s\n ",eventid,readUint32IP(addr))


		addr_len, err := getIntegerValue(buffer[16:24])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id(connect) %d => connect addr len: %d\n ",eventid,addr_len)

	}
	fmt.Println("-----------------------------------------")
	
	return iter.Err()
}

func formatmap_accept(m *ebpf.Map) (error) {
	var(
		
		key uint32
		val []byte// can we read a buffer here 
	)

	iter := m.Iterate()
	for iter.Next(&key,&val){
		eventid := key
		buffer := val

		fmt.Println("-----------------------------------------")
		sockfd, err := getIntegerValue(buffer[:8])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (accept)%d => Accept socket fd : %d\n ",eventid,sockfd)

		sockaddr, err := getIntegerValue(buffer[8:16])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (accept)%d => Accept soackaddr %s\n",eventid,readUint32IP(sockaddr))
/** have to work on accept system call's third argument addrlen (pointer to a structure)
		addrlen, err := getIntegerValue(buffer[16:24])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (accept) %d => Accept sockaddr addrlen: %d\n",eventid,addrlen)
		fmt.Println("-----------------------------------------")
	
**/
	
	}	
	return iter.Err()

}


func formatmap_bind(m *ebpf.Map) (error) {
	var(
		
		key uint32
		val []byte// can we read a buffer here 
	)

	iter := m.Iterate()
	for iter.Next(&key,&val){
		eventid := key
		buffer := val

		fmt.Println("-----------------------------------------")
		sockfd, err := getIntegerValue(buffer[:8])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (Bind)%d => Bind socket fd : %d\n ",eventid,sockfd)

		sockaddr, err := getIntegerValue(buffer[8:16])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (Bind) %d => Bind soackaddr %s\n",eventid,readUint32IP(sockaddr))

		addrlen, err := getIntegerValue(buffer[16:24])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (Bind) %d => Bind sockaddr addrlen: %d\n",eventid,addrlen)
		fmt.Println("-----------------------------------------")
	}
	
	return iter.Err()
}


func formatmap_listen(m *ebpf.Map) (error) {
	var(
		
		key uint32
		val []byte// can we read a buffer here 
	)

	iter := m.Iterate()
	for iter.Next(&key,&val){
		eventid := key
		buffer := val

		fmt.Println("-----------------------------------------")
		fd, err := getIntegerValue(buffer[:8])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (Listen) %d =>Listen socket fd : %d\n ",eventid,fd)

		backlog, err := getIntegerValue(buffer[8:16])
		if err != nil {
			fmt.Println("Error:", err)
		}
		fmt.Printf("\t Thread Id (Listen)  %d =>Listen Backlog: %d\n",eventid,backlog)
		fmt.Println("-----------------------------------------")
	}
	
	return iter.Err()

}



func getIntegerValue(buff []byte) (uint32, error) {
	var value uint32
	if len(buff) != 8 {
		return 0, fmt.Errorf("Input byte slice must have length 8")
	}

	err := binary.Read(bytes.NewBuffer(buff), binary.LittleEndian, &value)
	if err != nil {
		return 0, err
	}

	return value, nil
}


var socketDomains = map[uint32]string{
	0:  "AF_UNSPEC",
	1:  "AF_UNIX",
	2:  "AF_INET",
	3:  "AF_AX25",
	4:  "AF_IPX",
	5:  "AF_APPLETALK",
	6:  "AF_NETROM",
	7:  "AF_BRIDGE",
	8:  "AF_ATMPVC",
	9:  "AF_X25",
	10: "AF_INET6",
	11: "AF_ROSE",
	12: "AF_DECnet",
	13: "AF_NETBEUI",
	14: "AF_SECURITY",
	15: "AF_KEY",
	16: "AF_NETLINK",
	17: "AF_PACKET",
	18: "AF_ASH",
	19: "AF_ECONET",
	20: "AF_ATMSVC",
	21: "AF_RDS",
	22: "AF_SNA",
	23: "AF_IRDA",
	24: "AF_PPPOX",
	25: "AF_WANPIPE",
	26: "AF_LLC",
	27: "AF_IB",
	28: "AF_MPLS",
	29: "AF_CAN",
	30: "AF_TIPC",
	31: "AF_BLUETOOTH",
	32: "AF_IUCV",
	33: "AF_RXRPC",
	34: "AF_ISDN",
	35: "AF_PHONET",
	36: "AF_IEEE802154",
	37: "AF_CAIF",
	38: "AF_ALG",
	39: "AF_NFC",
	40: "AF_VSOCK",
	41: "AF_KCM",
	42: "AF_QIPCRTR",
	43: "AF_SMC",
	44: "AF_XDP",
}

// getSocketDomain Function
func getSocketDomain(sd uint32) string {
	// readSocketDomain prints the `domain` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html

	var res string

	if sdName, ok := socketDomains[sd]; ok {
		res = sdName
	} else {
		res = strconv.Itoa(int(sd))
	}

	return res
}

var socketTypes = map[uint32]string{
	1:  "SOCK_STREAM",
	2:  "SOCK_DGRAM",
	3:  "SOCK_RAW",
	4:  "SOCK_RDM",
	5:  "SOCK_SEQPACKET",
	6:  "SOCK_DCCP",
	10: "SOCK_PACKET",
}

func getSocketType(st uint32) string {
	// readSocketType prints the `type` bitmask argument of the `socket` syscall
	// http://man7.org/linux/man-pages/man2/socket.2.html
	// https://elixir.bootlin.com/linux/v5.5.3/source/arch/mips/include/asm/socket.h

	var f []string

	if stName, ok := socketTypes[st&0xf]; ok {
		f = append(f, stName)
	} else {
		f = append(f, strconv.Itoa(int(st)))
	}
	if st&000004000 == 000004000 {
		f = append(f, "SOCK_NONBLOCK")
	}
	if st&002000000 == 002000000 {
		f = append(f, "SOCK_CLOEXEC")
	}

	return strings.Join(f, "|")
}

var protocols = map[int32]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
	58: "ICMPv6",
}

// getProtocol Function
func getProtocol(proto int32) string {
	var res string

	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}

func readUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
}
