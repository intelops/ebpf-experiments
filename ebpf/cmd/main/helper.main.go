/**
*	Type: package
*	Name: main
*	Description: This file servers as a helper.
*				 It defines all the functions and
*			     types used by main package.
*
*	Authors: Charan Ravela
*	Created On: 04-25-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
 */
package main

import (
	"os"
	"os/signal"
	"syscall"
	"tarian/pkg/config"
	"tarian/pkg/ebpf"
	"tarian/pkg/file"
	"tarian/pkg/json"
	"tarian/pkg/misc"
	"tarian/pkg/progress"
	"tarian/pkg/time"
)

var signalToCapture []os.Signal = []os.Signal{
	os.Interrupt,
	syscall.SIGTERM,
	syscall.SIGINT,
	syscall.SIGQUIT,
	syscall.SIGUSR1,
	syscall.SIGUSR2,
}

/**
*	Type: function
*	Name: new
*	Description: This function creates a new instance
*				 of the `programContext` struct and
*				 initializes it with default values before
*				 returning the initialized struct.
*
*	Returns: A pointer to the programContext structure.
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func new() (pc *programContext) {
	pc = &programContext{}

	//initialize the statistics
	pc.stats.initialize()
	pc.currStats.initialize()

	//loads the config
	pc.config.loadConfig()

	//initialize the channels
	pc.channels.initialize()

	pc.should_stop = false

	pc.cache = initializeCache()
	return
}

/**
*	Type: function
*	Name: initialize
*	Description: This function sets the default values
*				 of the `programStats` struct
*
*
*	ReceiverType: *programStats
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (ps *programStats) initialize() {
	ps.totalCapturedCount = 0
	ps.totalExportSize = 0
	ps.totalFilesCount = 0
}

/**
*	Type: function
*	Name: initialize
*	Description: This function sets the default values
*				 of the `programChannels` struct
*
*
*	ReceiverType: *programChannels
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programChannels) initialize() {
	pc.exportChan = make(chan interface{})
	pc.common.DataChan = make(chan *ebpf.Event)
	pc.common.StopperChan = make(chan os.Signal)
}

/**
*	Type: function
*	Name: initializeCache
*	Description: This function returns the empty array of type ebpf.Event
*
*	Returns: []ebpf.Event
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func initializeCache() []ebpf.Event {
	return []ebpf.Event{}
}

/**
*	Type: function
*	Name: loadConfig
*	Description: This function loads the configuration file.
*
*	ReceiverType: *programConfig
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programConfig) loadConfig() {
	cnfg := getConfig()

	pc.showProgress = cnfg.ShowProgress.Enabled
	pc.printToScreen = cnfg.PrintToScreen.Enabled

	//exportAs
	for _, format := range cnfg.ExportAs {
		tempExp := exportOptions{}
		tempExp.enabled = format.Format.Enabled
		tempExp.format = format.Format.Value.(string)
		tempExp.directory = format.Directory.Value.(string)
		tempExp.exportOptions = []exportTrigger{
			{
				kind:    "time",
				enabled: format.ExportTrigger.Time.Enabled,
				value:   int(format.ExportTrigger.Time.Value.(float64)),
			}, {
				kind:    "count",
				enabled: format.ExportTrigger.Count.Enabled,
				value:   int(format.ExportTrigger.Count.Value.(float64)),
			}, {
				kind:    "size",
				enabled: format.ExportTrigger.Size.Enabled,
				value:   int(format.ExportTrigger.Size.Value.(float64)),
			},
		}
		pc.exportAs = append(pc.exportAs, tempExp)
	}
}

/**
*	Type: function
*	Name: start
*	Description: This function starts the ebpf programs.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) start() {
	for _, ebpf := range pc.ebpfPrograms {
		ebpf.Start()
	}
}

/**
*	Type: function
*	Name: stop
*	Description: This function stops the ebpf programs.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) stop() {
	for _, ebpf := range pc.ebpfPrograms {
		ebpf.Stop()
	}
}

/**
*	Type: function
*	Name: startExportAndTerminationSignals
*	Description: This function staarts export and termination signals.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) startExportAndTerminationSignals() {
	pc.channels.terminationSignal()
	pc.exportSignal()
}

/**
*	Type: function
*	Name: terminationSignal
*	Description: This function creates a termination signal.
*
*	ReceiverType: *programChannels
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-28-2023
*
 */
func (pc *programChannels) terminationSignal() {
	//Generates signal for program termination interupts
	signal.Notify(pc.common.StopperChan, signalToCapture...)
}

/**
*	Type: function
*	Name: exportSignal
*	Description: This function creates a export signal.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) exportSignal() {
	trigers := pc.config.exportAs[0].exportOptions
	for _, trg := range trigers {
		switch trg.kind {
		case "time":
			if trg.enabled {
				pc.timeExportSignal(trg.value)
			}
		case "count":
			if trg.enabled {
				pc.countExportSignal(trg.value)
			}
		case "size":
			if trg.enabled {
				pc.sizeExportSignal(trg.value)
			}
		}
	}
}

/**
*	Type: function
*	Name: timeExportSignal
*	Description: This function creates a time export signal.
*	Params:
*		-Name: freq
*		 Type: int
*		 Description: freq at which signal should be generated.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) timeExportSignal(freq int) {
	// Create a new ticker that will fire at the specified frequency
	ticker := time.Ticker(freq)
	defer ticker.Stop()

	go func() {
		for {
			select {
			case <-ticker.C:
				pc.channels.exportChan <- "time"
			case <-pc.channels.common.StopperChan:
				return
			}
		}
	}()
}

/**
*	Type: function
*	Name: countExportSignal
*	Description: This function creates a count export signal.
*	Params:
*		-Name: count
*		 Type: int
*		 Description: count at which signal should be generated.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) countExportSignal(count int) {
	go func() {
		for {
			if pc.should_stop {
				break
			}

			if pc.currStats.totalCapturedCount >= count {
				pc.channels.exportChan <- "count"
			}
		}
	}()
}

/**
*	Type: function
*	Name: sizeExportSignal
*	Description: This function creates a size export signal.
*	Params:
*		-Name: size
*		 Type: int
*		 Description: size at which signal should be generated.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) sizeExportSignal(size int) {
	//TODO: Need to implement size based exports.
}

/**
*	Type: function
*	Name: programProgress
*	Description: This function prints status to standard output.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) programProgress() {
	if pc.should_stop {
		if pc.config.exportAs[0].enabled {
			progress.Basic("Captured %d records. Exported to %d JSON files, total size: %.2f MB, at path:\n%s\n", pc.stats.totalCapturedCount, pc.stats.totalFilesCount, pc.stats.totalExportSize/(1024*1024), pc.config.exportAs[0].directory)
		} else {
			progress.Basic("Captured %d records. Exported to %d JSON files, total size: %.2f MB.\n", pc.stats.totalCapturedCount, pc.stats.totalFilesCount, pc.stats.totalExportSize/(1024*1024))
		}
	} else {
		progress.Basic("Captured %d records. Exported to %d JSON files, total size: %.2f MB.", pc.stats.totalCapturedCount, pc.stats.totalFilesCount, pc.stats.totalExportSize/(1024*1024))
	}
}

/**
*	Type: function
*	Name: export
*	Description: This function exports the information in desired file format.
*
*	ReceiverType: *programContext
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func (pc *programContext) export() {
	file.MkDirAll(pc.config.exportAs[0].directory)

	fnm := file.Join(pc.config.exportAs[0].directory, filename(pc.currStats.totalCapturedCount, pc.stats.totalFilesCount)+".json")

	fptr := file.CreateFile(fnm)
	json.WriteJson(fptr, pc.cache)

	pc.cache = initializeCache()
	pc.currStats.initialize()
	pc.stats.totalFilesCount++
	pc.stats.totalExportSize += float64(file.Size(fnm))
}

/**
*	Type: function
*	Name: getConfig
*	Description: This function fetchs the configuration file.
*
*	Returns: config.Config
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func getConfig() config.Config {
	return config.GetConfig()
}

/**
*	Type: function
*	Name: filename
*	Description: This function generates the file name.
*
*	Returns: string
*
*	Exported: false
*
*	Authors: Charan Ravela
*	Created On: 04-27-2023
*
*	Last Modified By: Charan Ravela
*	Last Modified: 04-27-2023
*
 */
func filename(rc int, fc int) string {
	return misc.FormatString("%s_%d_%d", time.Now("15 04 05"), fc, rc)
}
