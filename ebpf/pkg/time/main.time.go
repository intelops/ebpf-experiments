/**
*	Type: package
*	Name: time
*	Description: This package defines functions to work with
*                dates and times.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
 */
package time

import t "time"

/**
*	Type: DataType
*	Name: Tick
*	Description: This is an alias for t.Ticker
*
*
*	Authors: Charan Ravela
*	Created On: 04-17-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-17-2023
 */
type Tick t.Ticker

/**
*	Type: function
*	Name: Now
*	Params:
*		- Name:	layout
*		  Type: string
*		  Variadic: true
*		  Description: This expects the value defined
*                      in https://pkg.go.dev/time#pkg-constants
*	Returns: string
* 	Description: returns the current time as a string.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
*
 */
func Now(layout ...string) string {
	switch len(layout) {
	case 0:
		{
			return now()
		}
	case 1:
		{
			return format(layout[0])
		}
	default:
		{
			return ""
		}
	}
}

/**
*	Type: function
*	Name: GetTimestamp
*	Returns: string
* 	Description: returns the current time as a string.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-11-2023
 */
func GetTimestamp() string {
	return getTimestamp()
}

/**
*	Type: function
*	Name: Ticker
*	Params:
*		- Name: freq
*		  Type: int
*		  Description: rate at which ticker should send
*					   signals in miliseconds.
*
* 	Description: This function creates a ticker at specified
*				 frequency and return it.
*
*
*	Returns: *Tick
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-18-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-18-2023
 */
func Ticker(freq int) *Tick {
	return ticker(freq)
}

/**
*	Type: function
*	Name: Stop
*	Description: This function is used stop new ticker.
*
*	ReceiverType: *Tick
*
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-18-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-19-2023
*
 */
func (tk *Tick) Stop() {
	(*t.Ticker)(tk).Stop()
}
