package tmpl

import (
	"dllshimmer/dll"
	"log"
	"os"
	"path/filepath"
	"text/template"
)

type TemplateParams struct {
	Functions    []dll.ExportedFunction
	OriginalPath string
	DllName      string
	Mutex        bool
}

func CreateCodeFile(outputDir string, params TemplateParams, path string) {
	tmpl := template.Must(template.ParseFiles(path))

	f, err := os.Create(filepath.Join(outputDir, params.DllName+".cpp"))
	if err != nil {
		panic(err)
	}
	defer f.Close()

	err = tmpl.Execute(f, params)
	if err != nil {
		log.Fatalf("[!] Error of template engine: %v", err)
	}
}
