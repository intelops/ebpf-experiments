/**
*	Type: package
*	Name: file
*	Description: This package defines functions to work with file system.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
package file

import "os"

/**
*	Type: function
*	Name: CreateFile
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: This function create a file at specified
*					   path and return the pointer to the file.
*					   File ownership are inherited from the
*					   current executable.
*
*	Returns: *os.FIle
* 	Description: This function create a file at specified path and return
*				 the pointer to the file. File ownership are
*				 inherited from the current executable.
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
func CreateFile(filepath string) *os.File {
	return createFile(filepath)
}

/**
*	Type: function
*	Name: MkDirAll
*	Params:
*		- Name:	dirPath
*		  Type: string
*		  Description: This should be the path to the directory.
*
* 	Description: This function create a directory at the given
*                path along with any necessary parents.

*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
*
 */
func MkDirAll(dirPath string) {
	mkdirAll(dirPath)
}

/**
*	Type: function
*	Name: Size
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: Expected file path.
*
* 	Description: returns size of the file in bytes
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
*
 */
func Size(filepath string) int64 {
	return size(filepath)
}

/**
*	Type: function
*	Name: Open
*	Params:
*		- Name:	filepath
*		  Type: string
*		  Description: Expected file path.
*
* 	Description: opens the file at specified path and returns its pointer.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
*
 */
func Open(filepath string) *os.File {
	return open(filepath)
}

/**
*	Type: function
*	Name: ReadFile
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*	returns: []byte
*
* 	Description: reads the file at specified path and returns the byte array.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func ReadFile(filepath string) []byte {
	return readFile(filepath)
}

/**
*	Type: function
*	Name: GetCwd
*
*	returns: string
* 	Description: This function returns path of the
*			     current working directory.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func GetCwd() string {
	return getCwd()
}

/**
*	Type: function
*	Name: Join
*	Params:
*		- Name: paths
*		  Type: string
*		  Vardiac: true
*		  Description: paths to join together.
*
*	returns: string
* 	Description: This function concats the given
*				 paths and return them as one.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func Join(paths ...string) string {
	return join(paths...)
}
