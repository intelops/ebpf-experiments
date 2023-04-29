/**
*	Type: package
*	Name: json
*	Description: This package defines functions to work with json.
*
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
package json

import (
	"io"
)

/**
*	Type: function
*	Name: ReadJson
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: Expected json file path.
*
*	Returns: any
* 	Description: reads the json file at given path and returns the data.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
*
 */
func ReadJson(file io.Reader) interface{} {
	return readJson(file)
}

/**
*	Type: function
*	Name: ReadJsonInto
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: Expected json file path.
*		- Name: data
*		  Type: any
*		  Description:
*
* 	Description: reads the json file at given path and reads into data variable.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
*
 */
func ReadJsonInto(file string, data interface{}) {
	readJsonType(file, data)
}

/**
*	Type: function
*	Name: WriteJson
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: Expected json file path.
*		- Name: data
*		  Type: any
*		  Description: Data to write to file.
*
*	Returns: any
* 	Description: Writes the data to the json file at the given path.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
*
 */
func WriteJson(file io.Writer, data interface{}) {
	writeJson(file, data)
}

/**
*	Type: function
*	Name: GetField
*	Params:
*		- Name: src
*		  Type: any
*		  Description: source
*		- Name: key
*		  Type: string
*		  Description: path of the field.
*	returns: any
*
* 	Description: This function fetch value of field at given path
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func GetField(src interface{}, key string) interface{} {
	return get(src, key)
}
