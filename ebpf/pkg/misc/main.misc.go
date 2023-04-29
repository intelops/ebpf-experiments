/**
*	Type: package
*	Name: misc
*	Description: This package defines functions
*			     to work with common functonality.
*
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
 */
package misc

/**
*	Type: function
*	Name: Must
*	Params:
*		- Name: msg
*		  Type: string
*		  Description: message to print on screen before panicking.
*		- Name: err
*		  Type: error
*		  Description: error message
*
* 	Description: prints the message on the screen if there was a
*                error and panics.
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
func Must(msg string, err error) {
	must(msg, err)
}

/**
*	Type: function
*	Name: PrintMap
*	Params:
*		- Name: mp
*		  Type: map
*		  Description: expected map of key type string.
*
* 	Description: prints maps key and values to standard output.
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
func PrintMap(mp map[string]interface{}) {
	printMap(mp, true, 0)
}

/**
*	Type: function
*	Name: PrintMap
*	Params:
*		- Name: format
*		  Type: string
*		  Description: string format
*		- Name: args
*		  Type: any
*		  Variadic: true
*	returns: string
* 	Description: format the string and returns the resultant string.
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
func FormatString(format string, args ...interface{}) string {
	return formatString(format, args...)
}

/**
*	Type: function
*	Name: PrettyBytes
*	Params:
*		- Name: buf
*		  Type: []byte
*		  Description: raw byte array
*		- Name: data
*		  Type: any
*		  Description: pointer of the data type
* 	Description: returns the bytes in readable format.
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
func PrettyBytes(buf []byte, data interface{}) error {
	return prettyBytes(buf, data)
}

/**
*	Type: function
*	Name: RemoveNullBytes
*	Params:
*		- Name: arr
*		  Type: []uint8
*		  Description: source
* 	Description: removes the null bytes from the string and returns the string.
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
func RemoveNullBytes(arr []uint8) []uint8 {
	return removeNullBytes(arr)
}

/**
*	Type: function
*	Name: StructToMap
*	Params:
*		- Name: data
*		  Type: any
*		  Description: can be any struct
* 	Description: converts struct to map.
*
*	Returns: map[string]interface{}
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-13-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-13-2023
*
 */
func StructToMap(data interface{}) map[string]interface{} {
	return structToMap(data, true)
}

/**
*	Type: function
*	Name: SpreadMap
*	Params:
*		- Name: src
*		  Type: map[string]interface{}
*		  Description: source
*		- Name: dest
*		  Type: map[string]interface{}
*		  Description: destination
* 	Description: This function copies the fields of src
*				 to dest while preserving the value of dest.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
*
 */
func SpreadMap(src map[string]interface{}, dest map[string]interface{}) {
	spreadMap(src, dest)
}
