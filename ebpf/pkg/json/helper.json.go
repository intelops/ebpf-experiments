/**
*	Type: package
*	Name: json
*	Description: This package holds helper functions used by
*                exported json functions. This functions are not
*                visible outside of this package.
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
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"tarian/pkg/file"
)

/**
*	Type: function
*	Name: readJson
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*	returns: any
* 	Description: reads the json file at given path and returns the data.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func readJson(file io.Reader) interface{} {
	var data interface{}

	decoder := json.NewDecoder(file)
	decoder.Decode(&data)

	return data
}

/**
*	Type: function
*	Name: readJsonType
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*		- Name: data
*		  Type: any
*		  Description: this should be the type
*					   of data being read
*
* 	Description: reads the json file at given
*		    	 path and read data into data variable.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func readJsonType(filepath string, data interface{}) {
	fp := file.ReadFile(filepath)
	json.Unmarshal(fp, data)
}

/**
*	Type: function
*	Name: writeJson
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*		- Name: data
*		  Type: any
*		  Description: Data to write to file.
*	returns: int64
* 	Description: Writes the data to the json file at the given path.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func writeJson(file io.Writer, data interface{}) {
	encoder := json.NewEncoder(file)
	encoder.SetIndent(" ", "	")

	err := encoder.Encode(data)
	if err != nil {
		panic(err)
	}
}

/**
*	Type: function
*	Name: get
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
func get(src interface{}, key string) interface{} {
	paths := strings.SplitN(key, ".", 2)

	switch len(paths) {
	case 0:
		return nil
	case 2:
		return get(get(src, paths[0]), paths[1])
	default:
		typ := reflect.TypeOf(src)
		rVal := reflect.ValueOf(src)
		if typ == nil || typ.Kind().String() != "struct" {
			return nil
		}

		_, ok := typ.FieldByName(key)
		if ok {
			return rVal.FieldByName(key).Interface()
		} else {
			return nil
		}
	}
}
