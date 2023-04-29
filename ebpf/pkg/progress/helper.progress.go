/**
*	Type: package
*	Name: progress
*	Description: This package holds helper functions
*                used by exported progress functions.
*                This functions are not visible outside
*                of this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
package progress

import "fmt"

/**
*	Type: function
*	Name: basic
*	Params:
*		- Name: format
*		  Type: string
*		  Description: string format
*		- Name: args
*		  Type: any
*		  Variadic: true
*		  Description: This can be of any type.
*                      Format specifier in the fomat
*                      string will replace with the
*                      following arguments in the given order.
* 	Description: This prints the given format string
*                to standard output.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
func basic(format string, args ...interface{}) {
	format = format + "\r"

	fmt.Printf(format, args...)
}

/**
*	Type: function
*	Name: basicNoArgs
*	Params:
*		- Name: format
*		  Type: string
*		  Description: message string
* 	Description: This prints the given string to standard output.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
func basicNoArgs(format string) {
	format = format + "\r"

	fmt.Print(format)
}
