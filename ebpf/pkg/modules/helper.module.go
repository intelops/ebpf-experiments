/**
*	Type: package
*	Name: modules
*	Description: This holds the helper
*				 functions used by this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package modules

import (
	"tarian/pkg/ebpf"
	"tarian/pkg/ebpf/c/network"
	entry "tarian/pkg/ebpf/c/process_entry"
	exit "tarian/pkg/ebpf/c/process_exit"
)

/**
*	Type: function
*	Name: newEbpfs
*	Description: This function creates and intializes ebpfs
*				 with communication mechanism enabled and
*				 returns the pointer to the array.
*
*	Params:
*		-Name: com
*		 Type: ebpf.Communication
*		 Description: communication interface.
*
*	Returns: []*ebpf.EbpfHandlers
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
*
 */
func newEbpfs(com ebpf.Communication) []*ebpf.EbpfHandlers {
	var Ebpfs []*ebpf.EbpfHandlers = []*ebpf.EbpfHandlers{
		entry.GetEbpfObject().NewEbpf(com),
		exit.GetEbpfObject().NewEbpf(com),
		network.GetEbpfObject().NewEbpf(com),
	}

	return Ebpfs
}
