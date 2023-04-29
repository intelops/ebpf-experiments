/**
*	Type: package
*	Name: config
*	Description: This file defines the helper
*				 functions used by config package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package config

import (
	"fmt"
	"tarian/pkg/file"
	"tarian/pkg/json"
)

/**
*	Type: function
*	Name: restoreDefaultConfig
*	Description: This function restores the
* 				 configuration to its default values.
*	Params:
*		-Name: filepath
*		 Type: string
*		 Description: This is gonna be the path of the file.
*
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func restoreDefaultConfig(filepath string) {
	fptr := file.CreateFile(filepath)

	json.WriteJson(fptr, getDefaultConfig())

	fmt.Println("The configuration file has been successfully restored to its default values.")
}

/**
*	Type: function
*	Name: readConfig
*	Description: This function reads the config
*				 file and returns its content.
*	Params:
*		-Name: filepath
*		 Type: string
*		 Description: This is gonna be the path of the config file.
*
*	Returns: Config
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func readConfig(filepath string) Config {
	var confg Config

	json.ReadJsonInto(filepath, &confg)

	return confg
}

/**
*	Type: function
*	Name: getValue
*	Description: This function fetches the
*				 value of a config.
*
*	Params:
*		-Name: key
*		 Type: string
*		 Description: path of the key in th json structure.
*
*	ReceiverType: Config
*
*	Returns: interface{}
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (cfg Config) getValue(key string) interface{} {
	return json.GetField(cfg, key)
}

/**
*	Type: function
*	Name: getFilePath
*	Description: This function returns
*				 the path of the config file.
*
*
*	Returns: string
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func getFilePath() string {
	return configPath
}

/**
*	Type: function
*	Name: getDefaultConfig
*	Description: This function returns
*				 the values of default config.
*
*
*	Returns: Config
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func getDefaultConfig() Config {
	return defaultConfig
}
