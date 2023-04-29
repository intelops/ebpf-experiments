/**
*	Type: package
*	Name: progress
*	Description: This package defines functions
*                which helps to print the progress
*                of a program.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
package progress

/**
*	Type: function
*	Name: Basic
*	Params:
*		- Name: format
*		  Type: string
*		  Description: string format
*		- Name: args
*		  Type: any
*		  Variadic: true
*		  Description: This can be of any type.
*                      Format specifier in the fomat string
*                      will replace with the following arguments
*                      in the given order.
* 	Description: This prints the given string to standard output.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
func Basic(format string, args ...interface{}) {
	switch {
	case len(args) == 0:
		{
			basicNoArgs(format)
		}
	default:
		{
			basic(format, args...)
		}
	}
}
