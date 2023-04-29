/**
*	Type: package
*	Name: ebpf
*	Description: This package provides methods
*				 to work with ebpf programs.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package ebpf

import (
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

/**
*	Type: DataType
*	Name: Event
*	Description: The defines the infromation that
*				 a ebpf program should return.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type Event struct {
	Name       string
	Start_time string
	Hook       Hook
	Data       *interface{}
}

/**
*	Type: DataType
*	Name: Hook
*	Description: The defines hook information.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type Hook struct {
	Type    string
	Group   string
	Name    string
	XdpOpts link.XDPOptions
}

/**
*	Type: DataType
*	Name: Communication
*	Description: The defines the communication channels.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type Communication struct {
	StopperChan chan os.Signal
	DataChan    chan *Event
}

/**
*	Type: DataType
*	Name: EbpfProgram
*	Description: The defines ebpf program information.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type EbpfProgram struct {
	BpfHook    Hook
	BpfProgram *ebpf.Program
	BpfMap     *ebpf.Map
	DataType   interface{}
}

/**
*	Type: DataType
*	Name: EbpfHandlers
*	Description: The defines ebpf program return information.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type EbpfHandlers struct {
	evt       Event
	data_type interface{}

	Link      link.Link
	MapReader *ringbuf.Reader

	Comm Communication

	ShouldTerminate bool
}

/**
*	Type: function
*	Name: NewEbpf
*	Description: This function initializes the
*				 ebpf information.
*	Params:
*		-Name: com
*		 Type: Communication
*		 Description: communication channels
*
*	Returns: *EbpfHandlers
*	ReceiverType: EbpfProgram
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (ep EbpfProgram) NewEbpf(com Communication) *EbpfHandlers {
	eh, err := ep.newEbpf(com)
	if err != nil {
		panic(err)
	}

	return eh
}

/**
*	Type: function
*	Name: Start
*	Description: This function starts the ebpf programs.
*
*	ReceiverType: *EbpfHandlers
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (eh *EbpfHandlers) Start() {
	go eh.emit()
}

/**
*	Type: function
*	Name: Stop
*	Description: This function stops the ebpf programs.
*
*	ReceiverType: *EbpfHandlers
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
*
 */
func (eh *EbpfHandlers) Stop() {
	eh.close()
}
