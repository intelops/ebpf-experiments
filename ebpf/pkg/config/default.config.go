/**
*	Type: package
*	Name: config
*	Description: This file holds the default
*				 values used by this package.
*
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package config

import "tarian/pkg/file"

/**
*	Type: variable
*	Name: configPath
*	Description: This holds the file path
*				 the configuration file.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-24-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-26-2023
*
 */
var configPath string = file.GetCwd() + "/config.json"

/**
*	Type: variable
*	Name: defaultConfig
*	Description: This holds the default value of
*				 the configuration file.
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
var defaultConfig Config = Config{
	ShowProgress: Describe{
		Enabled:     true,
		Description: "Prints progress of application to standard output.",
	},
	PrintToScreen: Describe{
		Enabled:     false,
		Description: "Captured information will be printed to the standard console.",
	},
	ExportAs: []struct {
		Format        Describe
		Directory     Describe
		ExportTrigger ExportTrigger
	}{
		{
			Format: Describe{
				Value:       "JSON",
				Enabled:     false,
				Description: "Captured information will be exported in the specified 'Format'.",
			},
			Directory: Describe{
				Value:       file.Join(file.GetCwd(), "output"),
				Enabled:     false,
				Description: "This is going to be the output path of exported files",
			},
			ExportTrigger: ExportTrigger{
				Time: Describe{
					Value:       5,
					Enabled:     false,
					Description: "Data will be exported once for every 'Value' mili seconds.",
				},
				Count: Describe{
					Value:       100,
					Enabled:     false,
					Description: "Data will be exported for every 'Value' records captured.",
				},
				Size: Describe{
					Value:       1024,
					Enabled:     false,
					Description: "Data will be exported for every 'Value' Bytes of information captured.",
				},
			},
		},
	},
}
