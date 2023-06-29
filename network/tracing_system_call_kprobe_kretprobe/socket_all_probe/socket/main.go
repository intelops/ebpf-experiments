package main

import(
	"log"
	"os"
	"fmt"
	"encoding/binary"
	"bytes"
	"io"

	"strconv"
	"strings"
	"net"
	//"github.com/cilium/ebpf"
	//fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

)

const (
	intT          uint8 = 1
	strT          uint8 = 10
	strArrT       uint8 = 11
	sockAddrT     uint8 = 12
	openFlagsT    uint8 = 13
	execFlagsT    uint8 = 14
	sockDomT      uint8 = 15
	sockTypeT     uint8 = 16
	capT          uint8 = 17
	syscallT      uint8 = 18
	unlinkAtFlagT uint8 = 19
	ptraceReqT    uint8 = 23
	mountFlagT    uint8 = 24
	umountFlagT   uint8 = 25
	SyscallChannelSize = 1 << 13 //8192
	MaxStringLen     = 4096
)
type SyscallContext struct {
	Ts uint64

	PidID uint32
	MntID uint32

	HostPPID uint32
	HostPID  uint32

	PPID uint32
	PID  uint32
	UID  uint32

	EventID int32
	Argnum  int32
	Retval  int64

	Comm [16]byte
}
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf socket.c -- -I../headers

// main starts the x64_sys_socket kernel. It is called by kprobe and execve
func main() {

	

	// Name of the kernel function to trace.
	ebpf_accept := "__x64_sys_accept"
	ebpf_bind := "__x64_sys_bind"
	ebpf_connect := "__x64_sys_connect"
	ebpf_listen := "__x64_sys_listen"
	ebpf_socket := "__x64_sys_socket"
	fn_accept :="sys_accept"
	fn_bind := "sys_bind"
	fn_connect := "sys_connect"
	fn_listen := "sys_listen"
	fn_socket := "sys_socket"

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
		log.Fatalf("opening kprobe Accept: %s", err)
	}
	defer Accept.Close()


	Bind, err := link.Kprobe(ebpf_bind, objs.X64SysBind, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe Bind: %s", err)
	}
	defer Bind.Close()

// will emit an event containing pid and command of the execved task.
	Connect, err := link.Kprobe(ebpf_connect, objs.X64SysConnect, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe Connect: %s", err)
	}
	defer Connect.Close()

	Listen, err := link.Kprobe(ebpf_listen, objs.X64SysListen, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe Listen: %s", err)
	}
	defer Listen.Close()

	Socket, err := link.Kprobe(ebpf_socket, objs.X64SysSocket, nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kprobe Socket: %s", err)
	}
	defer Socket.Close()


	
	kp_socket, err := link.Kretprobe(fn_socket, objs.SysSocket,nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kretprobe socket: %s", err)
	}
	defer kp_socket.Close()

		
	kp_connect, err := link.Kretprobe(fn_connect, objs.SysConnect,nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kretprobe connect: %s", err)
	}
	defer kp_connect.Close()

	kp_accept, err := link.Kretprobe(fn_accept, objs.SysAccept,nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kretprobe accept: %s", err)
	}
	defer kp_accept.Close()

	kp_bind, err := link.Kretprobe(fn_bind, objs.SysBind,nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kretprobe bind: %s", err)
	}
	defer kp_bind.Close()

	kp_listen, err := link.Kretprobe(fn_listen, objs.SysListen,nil)
	// open kprobe if any error occurs
	if err != nil {
		log.Fatalf("opening kretprobe listen: %s", err)
	}
	defer kp_listen.Close()

	rd, err := perf.NewReader(objs.SysEvents,os.Getpagesize())
	if err != nil {
		log.Printf("failed to create perf event reader: %v", err)
		return
	}
	defer rd.Close()


	for {
		record, err := rd.Read()
		if err != nil {
			log.Printf("failed to read from perf ring buffer: %v", err)
			}
		
		dataBuff := bytes.NewBuffer(record.RawSample)
		ctx, err := readContextFromBuff(dataBuff)
		if err != nil {
			continue
		}
		GetArgs(dataBuff, ctx.Argnum)
    }
	}
	


func GetArgs(dataBuff *bytes.Buffer, Argnum int32) ([]interface{}, error) {
	args := []interface{}{}

	for i := 0; i < int(Argnum); i++ {
		arg, err := readArgFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		
		args = append(args, arg)
		fmt.Println("arguments are: \n",args)
	}

	return args, nil
}
func readArgFromBuff(dataBuff io.Reader) (interface{}, error) {
	var err error
	var res interface{}

	at, err := readArgTypeFromBuff(dataBuff)
	if err != nil {
		return res, fmt.Errorf("error reading argument type: %v", err)
	}
	fmt.Println("arguments type is : \n",at)

	switch at {
	case intT:
		res, err = readInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strT:
		res, err = readStringFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
	case strArrT:
		var ss []string
		et, err := readArgTypeFromBuff(dataBuff)
		if err != nil {
			return nil, fmt.Errorf("error reading string array element type: %v", err)
		}
		for et != strArrT {
			s, err := readStringFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string element: %v", err)
			}
			ss = append(ss, s)

			et, err = readArgTypeFromBuff(dataBuff)
			if err != nil {
				return nil, fmt.Errorf("error reading string array element type: %v", err)
			}
		}
		res = ss
	case sockAddrT:
		sockaddr, err := readSockaddrFromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = sockaddr
	case sockDomT:
		dom, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getSocketDomain(dom)
	case sockTypeT:
		t, err := readUInt32FromBuff(dataBuff)
		if err != nil {
			return nil, err
		}
		res = getSocketType(t)
	default:
		return nil, fmt.Errorf("error unknown argument type %v", at)
	}

	return res, nil
}

func readContextFromBuff(buff io.Reader) (SyscallContext, error) {
	var res SyscallContext
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err

}

func readArgTypeFromBuff(buff io.Reader) (uint8, error) {
	var res uint8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readInt32FromBuff(buff io.Reader) (int32, error) {
	var res int32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

func readStringFromBuff(buff io.Reader) (string, error) {
	var err error
	size, err := readInt32FromBuff(buff)
	if err != nil {
		return "", fmt.Errorf("error reading string size: %v", err)
	}
	if size == 0 {
		// empty string
		return "", nil
	}
	res, err := readByteSliceFromBuff(buff, int(size-1)) // last byte is string terminating null
	defer func() {
		_, _ = readInt8FromBuff(buff) // discard last byte which is string terminating null
	}()
	if err != nil {
		return "", fmt.Errorf("error reading string: %v", err)
	}
	return string(res), nil
}

func readSockaddrFromBuff(buff io.Reader) (map[string]string, error) {
	res := make(map[string]string, 3)
	family, err := readInt16FromBuff(buff)
	if err != nil {
		return nil, err
	}
	res["sa_family"] = getSocketDomain(uint32(family))
	switch family {
	case 1:
		 // AF_UNIX
		/*
			http://man7.org/linux/man-pages/man7/unix.7.html
			struct sockaddr_un {
					sa_family_t sun_family;     // AF_UNIX
					char        sun_path[108];  // Pathname
			};
		*/
		var sunPathBuf [108]byte
		err := binary.Read(buff, binary.LittleEndian, &sunPathBuf)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_un: %v", err)
		}

		sunPath := ""
		for i, v := range sunPathBuf {
			if v == '\u0000' { // null termination
				sunPath = string(sunPathBuf[:i])
				break
			}
		}
		res["sun_path"] = sunPath
	case 2: 
	// AF_INET
		/*
			http://man7.org/linux/man-pages/man7/ip.7.html
			struct sockaddr_in {
				sa_family_t    sin_family; // address family: AF_INET
				in_port_t      sin_port;   // port in network byte order
				struct in_addr sin_addr;   // internet address
			};
			struct in_addr {
				uint32_t       s_addr;     // address in network byte order
			};
		*/
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_port"] = strconv.Itoa(int(port))

		addr, err := readUInt32BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}
		res["sin_addr"] = readUint32IP(addr)
	case 10: 
	// AF_INET6
		// https://man7.org/linux/man-pages/man7/ipv6.7.html
		port, err := readUInt16BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing sockaddr_in: %v", err)
		}

		res["sin_port"] = strconv.Itoa(int(port))
		_, err = readUInt32BigendFromBuff(buff)
		if err != nil {
			return nil, fmt.Errorf("error parsing IPv6 flow information: %v", err)
		}
		addr, err := readByteSliceFromBuff(buff, 16)
		if err != nil {
			return nil, fmt.Errorf("error parsing IPv6 IP: %v", err)
		}
		ipv6 := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
		n := copy(ipv6, addr)
		if n != 16 {
			return nil, fmt.Errorf("error Converting bytes to IPv6, copied only %d bytes out of 16", n)
		}
		res["sin_addr"] = ipv6.String()
	}
	return res, nil
}

func readUInt32FromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
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
func readByteSliceFromBuff(buff io.Reader, len int) ([]byte, error) {
	res := []byte{}
	if len > 0 {
		res = make([]byte, Min(len, MaxStringLen))
		if err := binary.Read(buff, binary.LittleEndian, &res); err != nil {
			return nil, fmt.Errorf("error reading byte array: %v", err)
		}
		return res, nil
	}
	return nil, fmt.Errorf("error reading byte array: invalid len")
}

func readUInt16BigendFromBuff(buff io.Reader) (uint16, error) {
	var res uint16
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}

// readInt16FromBuff Function
func readInt16FromBuff(buff io.Reader) (int16, error) {
	var res int16
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readInt8FromBuff Function
func readInt8FromBuff(buff io.Reader) (int8, error) {
	var res int8
	err := binary.Read(buff, binary.LittleEndian, &res)
	return res, err
}

// readUInt32BigendFromBuff Function
func readUInt32BigendFromBuff(buff io.Reader) (uint32, error) {
	var res uint32
	err := binary.Read(buff, binary.BigEndian, &res)
	return res, err
}
func readUint32IP(in uint32) string {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, in)
	return ip.String()
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


func Min(a, b int) int {
	if a < b {
		return a
	}
	return b
}