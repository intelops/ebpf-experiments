/**
*	Type: package
*	Name: json
*	Description: This package holds helper functions used by
*                exported misc functions. This functions are not
*                visible outside of this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
 */
package misc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"reflect"
	"strings"
)

/**
*	Type: function
*	Name: must
*	Params:
*		- Name: msg
*		  Type: string
*		  Description: message to print on screen before panicking.
*		- Name: err
*		  Type: error
*		  Description: error
* 	Description: prints the message on the screen if there was a
*                error and panics.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func must(msg string, err error) {
	if err != nil {
		fmt.Printf("\n%s: %v\n", msg, err)
		os.Exit(1)
	}
}

/**
*	Type: function
*	Name: printMap
*	Params:
*		- Name: mp
*		  Type: map
*		  Description: expected map of key type string.
*
* 	Description: prints maps key and values to standard output.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func printMap(mp map[string]interface{}, divide bool, level int) {
	if divide {
		divider("-", 50)
	}

	for ky, vl := range mp {
		switch getType(vl) {
		case "map":
			fmt.Printf("%s%s: {\n", repeat("\t", level), ky)
			if subMap, ok := vl.(map[string]interface{}); ok {
				printMap(subMap, false, level+1)
			}
			fmt.Printf("%s}\n", repeat("\t", level))
		case "struct":
			fmt.Printf("%s%s: {\n", repeat("\t", level), ky)
			printMap(structToMap(vl, true), false, level+1)
			fmt.Printf("%s}\n", repeat("\t", level))
		default:
			fmt.Printf("%s%s: %v\n", repeat("\t", level), ky, vl)
		}
	}

	if divide {
		divider("-", 50)
	}
}

/**
*	Type: function
*	Name: divider
*	Params:
*		- Name: sym
*		  Type: string
*		  Description: symbol to print to stdout
*		- Name: rep
*		  Type: int
*		  Description: number of times the symbol should repeat.
*
* 	Description: prints symbol to standard output rep times.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func divider(sym string, rep int) {
	sym = repeat(sym, rep)

	fmt.Println(sym)
}

/**
*	Type: function
*	Name: formatString
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
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func formatString(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

/**
*	Type: function
*	Name: toString
*	Params:
*		- Name: data
*		  Type: any
*		  Description: any value.
*	Returns: string
* 	Description: convert given info to string using fmt.Sprintf
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func toString(data interface{}) string {
	str := fmt.Sprintf("%s", data)

	return str
}

/**
*	Type: function
*	Name: prettyBytes
*	Params:
*		- Name: buf
*		  Type: []byte
*		  Description: raw byte array
*		- Name: data
*		  Type: any
*		  Description: pointer of the data type
* 	Description: returns the bytes in readable format.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-18-2023
 */
func prettyBytes(buf []byte, data interface{}) error {
	err := binary.Read(bytes.NewBuffer(buf), binary.LittleEndian, data)
	if err != nil {
		return err
	}

	return nil
}

/**
*	Type: function
*	Name: removeNullBytes
*	Params:
*		- Name: arr
*		  Type: []uint8
*		  Description: source
* 	Description: removes the null bytes from the array and returns the array.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-17-2023
 */
func removeNullBytes(arr []uint8) []uint8 {
	idx := indexOf(arr, 0)
	return arr[:idx]
}

/**
*	Type: function
*	Name: structToMap
*	Params:
*		- Name: data
*		  Type: any
*		  Description: can be any struct
*		- Name: shouldBeStruct
*		  Type: bool
*         Description: whether the data
*					   neccessarliy be the struct.
* 	Description: converts struct to map.
*
*	Returns: map[string]interface{}
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-13-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
 */
func structToMap(data interface{}, shoulbBeStruct bool) map[string]interface{} {
	dataMap := map[string]interface{}{}

	typeData := reflect.TypeOf(data)
	if typeData.Kind() != reflect.Struct && shoulbBeStruct {
		return dataMap
	} else if typeData.Kind() == reflect.Ptr {
		if reflect.ValueOf(data).IsNil() {
			return nil
		}

		return structToMap(reflect.ValueOf(data).Elem().Interface(), false)
	}

	valueData := reflect.ValueOf(data)
	for i := 0; i < valueData.NumField(); i++ {
		if !typeData.Field(i).IsExported() {
			continue
		}

		currFieldType := typeData.Field(i).Type
		currFieldName := typeData.Field(i).Name
		currFieldValue := valueData.Field(i)

		switch currFieldType.Kind() {
		case reflect.String:
			dataMap[currFieldName] = currFieldValue.String()

		case reflect.Ptr:
			if currFieldValue.IsNil() {
				dataMap[currFieldName] = nil
				continue
			}

			dataMap[currFieldName] = structToMap(currFieldValue.Elem().Interface(), false)

		case reflect.Struct:
			dataMap[currFieldName] = structToMap(currFieldValue.Interface(), true)

		case reflect.Array:
			switch currFieldType.Elem().Kind() {
			case reflect.Array:
				switch currFieldValue.Type().Elem().Elem().Kind() {
				case reflect.Uint8:
					var str string
					for j := 0; j < currFieldValue.Len(); j++ {
						currStr := uint8ToString(toUint8Slice(currFieldValue.Index(j)))
						if len(currStr) > 0 {
							if len(str) != 0 {
								str += " " + currStr
							} else {
								str = currStr
							}
						}
					}

					dataMap[currFieldName] = str

				default:
					dataMap[currFieldName] = toString(currFieldValue)
				}
			case reflect.Uint8:
				sanitize := toUint8Slice(currFieldValue)
				dataMap[currFieldName] = toString(sanitize)

			default:
				dataMap[currFieldName] = currFieldValue.Interface()
			}

		case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			dataMap[currFieldName] = currFieldValue.Uint()

		case reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			dataMap[currFieldName] = currFieldValue.Int()

		case reflect.Float32, reflect.Float64:
			dataMap[currFieldName] = currFieldValue.Float()

		default:
			dataMap[currFieldName] = currFieldValue.Interface()

		}
	}

	return dataMap
}

/**
*	Type: function
*	Name: indexOf
*	Params:
*		- Name: arr
*		  Type: []uint8
*		  Description: source
*		- Name: val
*		  Type: uint8
*		  Description: element to remove
*	Returns: int
* 	Description: matches the val with element of arr and returns its index. If not found returns -1
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-17-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-17-2023
 */
func indexOf(arr []uint8, val uint8) int {
	for idx, ele := range arr {
		if ele == val {
			return idx
		}
	}

	return -1
}

/**
*	Type: function
*	Name: uint8ToString
*	Params:
*		- Name: arr
*		  Type: []uint8
*		  Description: source
*	Returns: string
* 	Description: converts the given uint8 array to string. If there are null bytes it removes them.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-17-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-17-2023
 */
func uint8ToString(arr []uint8) string {
	arr = removeNullBytes(arr)

	return toString(arr)
}

/**
*	Type: function
*	Name: toUint8Slice
*	Params:
*		- Name: arr
*		  Type: reflect,Value
*		  Description: source
*	Returns: [] uint8
* 	Description: converts the reflect.Value to uint8 slice. panics if value id not of type uint8 array or slice.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-17-2023
 */
func toUint8Slice(arr reflect.Value) []uint8 {
	if arr.Type().Elem().Kind() != reflect.Uint8 {
		panic("Type mismacth: Expected []uint8 array or slice")
	}

	slice := reflect.MakeSlice(reflect.SliceOf(reflect.TypeOf(uint8(0))), arr.Len(), arr.Len())
	reflect.Copy(slice, arr)

	return slice.Bytes()
}

/**
*	Type: function
*	Name: spreadMap
*	Params:
*		- Name: src
*		  Type: map[string]interface{}
*		  Description:	source
*		- Name: dest
*		  Type: map[string]interface{}
*		  Description: destination
* 	Description: This function copies the fields of src
*				 to dest while preserving the value of dest.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
 */
func spreadMap(src map[string]interface{}, dest map[string]interface{}) {
	for key, val := range src {
		dest[key] = val
	}
}

/**
*	Type: function
*	Name: getType
*	Params:
*		- Name: value
*		  Type: any
*		  Description: It can be any valid value.

* 	Description: This function returns the type of field.
*
*	Returns: string
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
 */
func getType(value interface{}) string {
	if !reflect.ValueOf(value).IsValid() {
		return ""
	}
	return reflect.TypeOf(value).Kind().String()
}

/**
*	Type: function
*	Name: repeat
*	Params:
*		- Name: str
*		  Type: string
*		  Description: string to repeat.
*		- Name: rep
*		  Type: int
*		  Description: number of times to repeat.
*
* 	Description: repeats the given str rep times and returns its.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-20-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-20-2023
 */
func repeat(str string, rep int) string {
	return strings.Repeat(str, rep)
}
