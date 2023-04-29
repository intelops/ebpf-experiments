/**
*	Type: package
*	Name: modules
*	Description: This package provides functions for
*				 creating and managing eBPF programs
*				 used in this application.
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
)

/**
*	Type: function
*	Name: NewEbpfs
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
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
*
 */
func NewEbpfs(com ebpf.Communication) []*ebpf.EbpfHandlers {
	return newEbpfs(com)
}
