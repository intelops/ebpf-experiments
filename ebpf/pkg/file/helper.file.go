/**
*	Type: package
*	Name: file
*	Description: This package holds helper functions used by
*                exported file functions. This functions are not
*                visible outside of this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
package file

import (
	"io/fs"
	"os"
	"path"
	"strings"
	"syscall"
)

/**
*	Type: function
*	Name: createFile
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: This should be the path of the file.
*	Returns: *os.FIle
* 	Description: This function create a file at specified path and return
*				 the pointer to the file. File ownership is
*				 inherited from the current executable.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-11-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func createFile(filepath string) *os.File {
	file, err := os.Create(filepath)
	if err != nil {
		panic(err)
	} else {
		uid, gid, _ := getExeOwnerAndPerm()
		if err := file.Chmod(0664); err != nil {
			panic(err)
		}

		if err := file.Chown(uid, gid); err != nil {
			panic(err)
		}
	}

	return file
}

/**
*	Type: function
*	Name: getExeOwnerAndPerm
*	Returns: int, int, fs.FileMode
* 	Description: This function return the ownership
*				 and file permission of currently
*				 executing program.
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func getExeOwnerAndPerm() (int, int, fs.FileMode) {
	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	file, err := os.Stat(ex)
	if err != nil {
		panic(err)
	}
	return int(file.Sys().(*syscall.Stat_t).Uid), int(file.Sys().(*syscall.Stat_t).Gid), file.Mode().Perm()
}

/**
*	Type: function
*	Name: mkdirAll
*	Params:
*		- Name: dirPath
*		  Type: string
*		  Description: This should be the path to the directory.
* 	Description: This function create a directory at the given
*                path along with any necessary parents. File ownership is
*				 inherited from the current executable.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func mkdirAll(dirPath string) {
	if strings.HasPrefix(dirPath, "/") {
		dirPath = strings.Replace(dirPath, "/", "", 1)
	}

	subDirs := strings.Split(dirPath, "/")
	currPath := ""

	for _, dir := range subDirs {
		currPath += "/" + dir

		currStat := dirExist(currPath)
		if !currStat {
			err := os.Mkdir(currPath, 0775)
			if err != nil {
				panic(err)
			}

			uid, gid, _ := getExeOwnerAndPerm()
			err = os.Chown(currPath, uid, gid)
			if err != nil {
				panic(err)
			}
		}
	}
}

/**
*	Type: function
*	Name: dirExist
*	Params:
*		- Name: dirPath
*		  Type: string
*		  Description: This should be the path to the directory.
*
*	returns: bool
* 	Description: returns true if directory path exists else false.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func dirExist(dirPath string) bool {
	_, err := os.Stat(dirPath)
	if err != nil {
		return !os.IsNotExist(err)
	}

	return true
}

/**
*	Type: function
*	Name: size
*	Params:
*		- Name: filePtr
*		  Type: *os.File
*		  Description: Expected file path.
*	returns: int64
* 	Description: returns size of the file in bytes
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func size(filepath string) int64 {
	info, err := os.Stat(filepath)
	if err != nil {
		panic(err)
	}

	return info.Size()
}

/**
*	Type: function
*	Name: open
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*	returns: *os.File
* 	Description: opens the file at specified path and returns its pointer.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-12-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-12-2023
 */
func open(filepath string) *os.File {
	fp, err := os.Open(filepath)
	if err != nil {
		panic(err)
	}

	return fp
}

/**
*	Type: function
*	Name: readFile
*	Params:
*		- Name: filepath
*		  Type: string
*		  Description: Expected file path.
*	returns: []byte
* 	Description: reads the file at specified path and returns the byte array.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func readFile(filepath string) []byte {
	fp, err := os.ReadFile(filepath)
	if err != nil {
		panic(err)
	}

	return fp
}

/**
*	Type: function
*	Name: getCwd
*
*	returns: string
* 	Description: This function returns path of the
*			     current working directory.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func getCwd() string {
	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	return path
}

/**
*	Type: function
*	Name: join
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
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
 */
func join(paths ...string) string {
	return path.Join(paths...)
}
