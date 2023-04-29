/**
*	Type: package
*	Name: config
*	Description: This package contains functions
*				 that enable the setup of configurations
*				 for the application.
*
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package config

/**
*	Type: DataType
*	Name: Config
*	Description: This structure defines the config
*				 struture of the application.
*
*
*	Authors: Charan Ravela
*	Created On: 04-17-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type Config struct {
	ShowProgress  Describe
	PrintToScreen Describe
	ExportAs      []struct {
		Format        Describe
		Directory     Describe
		ExportTrigger ExportTrigger
	}
}

/**
*	Type: DataType
*	Name: ExportOptions
*	Description: This structure defines the
*				 export triggers.
*
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type ExportTrigger struct {
	Time  Describe
	Count Describe
	Size  Describe
}

/**
*	Type: DataType
*	Name: Describe
*	Description: This structure defines what field
*				 value should have.
*
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
type Describe struct {
	Value       interface{}
	Enabled     bool
	Description string
}

/**
*	Type: function
*	Name: DefaultConfig
*	Description: This function restores the
* 				 configuration to its default values.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func DefaultConfig() {
	restoreDefaultConfig(getFilePath())
}

/**
*	Type: function
*	Name: GetConfig
*	Description: This function fetches the config
*				 from the file and returns its content.
*
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func GetConfig() Config {
	return readConfig(getFilePath())
}

/**
*	Type: function
*	Name: GetValue
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
*	Exported: true
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-25-2023
*
 */
func (cfg Config) GetValue(key string) interface{} {
	return cfg.getValue(key)
}
