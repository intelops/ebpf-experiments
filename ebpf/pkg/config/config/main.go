/**
*	Type: package
*	Name: main
*	Description: The file serves as the
*                driver for the application,
*				 to reset the configuration
*				 to its default values.
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-24-2023
 */
package main

import "tarian/pkg/config"

/**
*	Type: function
*	Name: main
*	Description: This makes a call to function
*				 which resets the configuration file.
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
func main() {
	config.DefaultConfig()
}
