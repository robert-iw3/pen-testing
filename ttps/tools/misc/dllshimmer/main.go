package main

import (
	"dllshimmer/cli"
	"dllshimmer/def"
	"dllshimmer/dll"
	"dllshimmer/tmpl"
	"fmt"
	"path/filepath"
)

func main() {
	flags := cli.ParseCli()

	outputDir := filepath.Clean(flags.Output)

	dll := dll.ParseDll(flags.Input)

	var params tmpl.TemplateParams
	params.Functions = dll.ExportedFunctions
	params.OriginalPath = flags.OriginalPath
	params.DllName = filepath.Base(flags.Input)
	params.Mutex = flags.Mutex

	if flags.Static {
		tmpl.CreateCodeFile(outputDir, params, "templates/static-shim.c.template")

		// Create .lib based on original DLL
		dll.CreateLibFile(filepath.Join(outputDir, "original.lib"), params.OriginalPath)
	} else {
		tmpl.CreateCodeFile(outputDir, params, "templates/dynamic-shim.c.template")
	}

	func() {
		var def def.DefFile
		def.DllName = params.DllName

		for _, function := range dll.ExportedFunctions {
			if function.Forwarder == "" {
				def.AddRenamedFunction(function.Name, function.Name+"Fwd", function.Ordinal)
			} else {
				def.AddForwardedFunction(function.Name, function.Forwarder, function.Ordinal)
			}
		}

		def.SaveFile(filepath.Join(outputDir, params.DllName+".def"), true)
	}()

	codeFile := filepath.Join(outputDir, params.DllName+".cpp")
	defFile := filepath.Join(outputDir, params.DllName+".def")
	dllFile := filepath.Join(outputDir, params.DllName)

	var cmd string
	if flags.Static {
		cmd = fmt.Sprintf(
			"x86_64-w64-mingw32-g++ -shared %s %s -o %s -L %s -l original -static-libstdc++ -static-libgcc -D DEBUG=1",
			codeFile,
			defFile,
			dllFile,
			outputDir,
		)
	} else {
		cmd = fmt.Sprintf(
			"x86_64-w64-mingw32-g++ -shared %s %s -o %s -static-libstdc++ -static-libgcc -D DEBUG=1",
			codeFile,
			defFile,
			dllFile,
		)
	}

	println(cmd)
}
