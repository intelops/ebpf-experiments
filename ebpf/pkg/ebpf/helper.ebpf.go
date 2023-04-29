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
		eh.evt.Data = &eh.data_type
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
