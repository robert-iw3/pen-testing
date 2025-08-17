package dll

import (
	"dllshimmer/def"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	peparser "github.com/saferwall/pe"
)

type ExportedFunction struct {
	Name      string
	Forwarder string
	Ordinal   uint32
}

type Dll struct {
	Name              string
	ExportedFunctions []ExportedFunction
}

func ParseDll(path string) *Dll {
	var dll Dll

	dll.Name = filepath.Base(path)

	pe, err := peparser.New(path, &peparser.Options{})
	if err != nil {
		log.Fatalf("[!] Error while opening file: %s, reason: %v", path, err)
	}

	err = pe.Parse()
	if err != nil {
		log.Fatalf("[!] Error while parsing file: %s, reason: %v", path, err)
	}

	for _, function := range pe.Export.Functions {
		dll.ExportedFunctions = append(dll.ExportedFunctions, ExportedFunction{
			Name:      function.Name,
			Forwarder: function.Forwarder,
			Ordinal:   function.Ordinal,
		})
	}

	return &dll
}

func (d *Dll) CreateLibFile(path string, proxyName string) {
	var def def.DefFile
	def.DllName = proxyName

	for _, function := range d.ExportedFunctions {
		if function.Forwarder == "" {
			def.AddExportedFunction(function.Name, function.Ordinal)
		} else {
			def.AddForwardedFunction(function.Name, function.Forwarder, function.Ordinal)
		}
	}

	f, err := os.CreateTemp("", "dllshimmer-*.def")
	if err != nil {
		panic(err)
	}
	defer os.Remove(f.Name())

	def.SaveFile(f.Name(), true)

	// Convert DLL to .lib file
	cmd := exec.Command("x86_64-w64-mingw32-dlltool", "-d", f.Name(), "-l", path, "-m", "i386:x86-64")
	_, err = cmd.CombinedOutput()
	if err != nil {
		panic(err)
	}
}
