/**
*	Type: package
*	Name: time
*	Description: This package holds helper functions
*                used by exported time functions. This
*				 functions are not visible outside of this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
 */

package time

import (
	t "time"
)

/**
*	Type: function
*	Name: now
*	Returns: string
* 	Description: returns the current time as a string.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023

 */
func now() string {
	return t.Now().String()
}

/**
*	Type: function
*	Name: format
*	Params:
*		- Name: layout
*		  Type: string
*		  Description: This expects the value defined in
* 				       https://pkg.go.dev/time#pkg-constants
*	Returns: string
* 	Description: returns the current time as a string in the
*				 given layout string format.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023

 */
func format(layout string) string {
	return t.Now().Format(layout)
}

/**
*	Type: function
*	Name: getTimestamp
*	Returns: string
* 	Description: returns the current time as a string in format
*                "monjan_2_150405.999999999Z07_MST_2006".
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023

 */
func getTimestamp() string {
	return format("monjan_2_150405.999999999Z07_MST_2006")
}

/**
*	Type: function
*	Name: ticker
*	Params:
*		- Name: freq
*		  Type: int
*		  Description: rate at which ticker should send
*					   signals in miliseconds.
*
* 	Description: This function creates a ticker at specified
*				 frequency and return it.
*
*	Returns: *Tick
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-18-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-18-2023

 */
func ticker(freq int) *Tick {
	return (*Tick)(t.NewTicker(t.Duration(freq) * t.Millisecond))
}
