package renderer

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/praetorian-inc/OAuthSeeker/static"
)

type Renderer struct {
	baseTemplate *template.Template
	viewTemplate *template.Template
}

func NewRenderer(viewName string) (*Renderer, error) {
	baseTemplateContent, err := fs.ReadFile(static.AdminPanelTemplates, "admin/templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("error reading base template: %v", err)
	}

	baseTemplate, err := template.New("base").Parse(string(baseTemplateContent))
	if err != nil {
		return nil, fmt.Errorf("error parsing base template: %v", err)
	}

	viewTemplatePath := fmt.Sprintf("admin/templates/%s.html", viewName)
	viewTemplateContent, err := fs.ReadFile(static.AdminPanelTemplates, viewTemplatePath)
	if err != nil {
		return nil, fmt.Errorf("error reading view template %s: %v", viewName, err)
	}

	viewTemplate, err := baseTemplate.Clone()
	if err != nil {
		return nil, fmt.Errorf("error cloning base template: %v", err)
	}

	_, err = viewTemplate.Parse(string(viewTemplateContent))
	if err != nil {
		return nil, fmt.Errorf("error parsing view template %s: %v", viewName, err)
	}

	return &Renderer{
		baseTemplate: baseTemplate,
		viewTemplate: viewTemplate,
	}, nil
}

func (r *Renderer) Render(w http.ResponseWriter, data interface{}) error {
	err := r.viewTemplate.ExecuteTemplate(w, "base", data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return fmt.Errorf("error rendering template: %v", err)
	}
	return nil
}
