/**
*	Type: package
*	Name: ebpf
*	Description: This package provides helper
*				 functions used by this package.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package ebpf

import (
	"strconv"
	"strings"
	"tarian/pkg/misc"
	"tarian/pkg/time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

/**
*	Type: function
*	Name: attachHook
*	Description: This function attach the ebpf programs.
*
*	Returns: link.Link, error
*	ReceiverType: *EbpfProgram
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (ep *EbpfProgram) attachHook() (link.Link, error) {
	var hook link.Link
	var err error

	switch ep.BpfHook.Type {
	case "tracepoint":
		hook, err = link.Tracepoint(ep.BpfHook.Group, ep.BpfHook.Name, ep.BpfProgram, nil)
	case "xdp":
		hook, err = link.AttachXDP(ep.BpfHook.XdpOpts)
	case "kprobe":
		hook, err = link.Kprobe(ep.BpfHook.Name, ep.BpfProgram, nil)
	}

	if err != nil {
		return nil, err
	}

	return hook, nil
}

/**
*	Type: function
*	Name: mapReader
*	Description: This function creates new map
*			     instance and returns it.
*
*	Returns: *ringbuf.Reader, error
*	ReceiverType: *EbpfProgram
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (ep *EbpfProgram) mapReader() (*ringbuf.Reader, error) {
	BpfMapReader, err := ringbuf.NewReader(ep.BpfMap)
	if err != nil {
		return nil, err
	}

	return BpfMapReader, nil
}

/**
*	Type: function
*	Name: newEbpf
*	Description: This function initializes the
*				 ebpf information.
*	Params:
*		-Name: com
*		 Type: Communication
*		 Description: communication channels
*		-Name: err
*		 Type: error
*		 Description: error
*
*	Returns: *EbpfHandlers
*	ReceiverType: EbpfProgram
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (ep *EbpfProgram) newEbpf(comm Communication) (*EbpfHandlers, error) {
	var err error
	eh := &EbpfHandlers{
		Comm: comm,
	}
	eh.data_type = ep.DataType
	eh.evt.Start_time = time.Now()
	eh.evt.Hook = ep.BpfHook

	eh.Link, err = ep.attachHook()
	if err != nil {
		return nil, err
	}

	eh.MapReader, err = ep.mapReader()
	if err != nil {
		return nil, err
	}

	return eh, nil
}

/**
*	Type: function
*	Name: emit
*	Description: This function starts the ebpf programs.
*
*	ReceiverType: *EbpfHandlers
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (eh *EbpfHandlers) emit() {
	for {
		if eh.ShouldTerminate {
			break
		}

		record, err := eh.MapReader.Read()
		if err != nil {
			continue
		}

		misc.PrettyBytes(record.RawSample, eh.data_type)
		if eh.evt.Hook.Name == "__x64_sys_socket" {
			temp := sanitize(eh.data_type)

			eh.evt.Data = &temp
		} else {
			eh.evt.Data = &eh.data_type
		}

		eh.Comm.DataChan <- &eh.evt
	}
}

/**
*	Type: function
*	Name: close
*	Description: This function stops the ebpf programs.
*
*	ReceiverType: *EbpfHandlers
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (eh *EbpfHandlers) close() {
	eh.ShouldTerminate = true

	if eh.Link != nil {
		eh.Link.Close()
	}

	if eh.MapReader != nil {
		eh.MapReader.Close()
	}
}

func sanitize(obj interface{}) interface{} {
	type Network struct {
		Family   string
		Protocol string
		Type     string
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

	var socketTypes = map[uint32]string{
		1:  "SOCK_STREAM",
		2:  "SOCK_DGRAM",
		3:  "SOCK_RAW",
		4:  "SOCK_RDM",
		5:  "SOCK_SEQPACKET",
		6:  "SOCK_DCCP",
		10: "SOCK_PACKET",
	}

	var protocols = map[int32]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
		58: "ICMPv6",
	}

	var res Network
	temp := misc.AnyToMap(obj)

	family, _ := temp["Family"].(uint64)
	typ, _ := temp["Type"].(uint64)
	proto, _ := temp["Protocol"].(int64)

	res.Family = getSocketDomain(socketDomains, uint32(family))
	res.Protocol = getProtocol(protocols, int32(proto))
	res.Type = getSocketType(socketTypes, uint32(typ))

	return res
}

// getSocketDomain Function
func getSocketDomain(socketDomains map[uint32]string, sd uint32) string {
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

// getProtocol Function
func getProtocol(protocols map[int32]string, proto int32) string {
	var res string

	if protoName, ok := protocols[proto]; ok {
		res = protoName
	} else {
		res = strconv.Itoa(int(proto))
	}

	return res
}

func getSocketType(socketTypes map[uint32]string, st uint32) string {
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
