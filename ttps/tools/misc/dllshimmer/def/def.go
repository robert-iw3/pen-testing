package def

import (
	"fmt"
	"log"
	"os"
)

type exportedFunction struct {
	OriginalName string
	Rename       string
	Forwarder    string
	Ordinal      uint32
}

type DefFile struct {
	DllName           string
	exportedFunctions []exportedFunction
}

func (d *DefFile) AddExportedFunction(name string, ordinal uint32) {
	d.exportedFunctions = append(d.exportedFunctions, exportedFunction{
		OriginalName: name,
		Ordinal:      ordinal,
	})
}

func (d *DefFile) AddRenamedFunction(originalName string, rename string, ordinal uint32) {
	d.exportedFunctions = append(d.exportedFunctions, exportedFunction{
		OriginalName: originalName,
		Rename:       rename,
		Ordinal:      ordinal,
	})
}

func (d *DefFile) AddForwardedFunction(originalName string, forwarder string, ordinal uint32) {
	d.exportedFunctions = append(d.exportedFunctions, exportedFunction{
		OriginalName: originalName,
		Forwarder:    forwarder,
		Ordinal:      ordinal,
	})
}

func (d *DefFile) SaveFile(path string, withOrdinals bool) {
	var content string

	content += "LIBRARY \"" + d.DllName + "\"\n"
	content += "EXPORTS\n"

	for _, function := range d.exportedFunctions {
		if function.Forwarder == "" && function.Rename == "" {
			content += "\t" + function.OriginalName
		}

		if function.Forwarder != "" {
			// Forwarded functions
			content += "\t" + function.OriginalName + "=" + function.Forwarder
		}

		if function.Rename != "" {
			// Exported-renamed functions
			content += "\t" + function.OriginalName + "=" + function.Rename
		}

		if withOrdinals {
			content += " " + "@" + fmt.Sprintf("%d", function.Ordinal)
		}

		content += "\n"
	}

	err := os.WriteFile(path, []byte(content), 0644)
	if err != nil {
		log.Fatalf("[!] Error while creating .def file: %v", err)
	}
}
