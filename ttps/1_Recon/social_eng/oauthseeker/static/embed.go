package static

import (
	"embed"
	_ "embed"
)

//go:embed skins/default/success.html
var DefaultSuccessHTML []byte

//go:embed skins/default/error.html
var DefaultErrorHTML []byte

//go:embed admin/static/*
var AdminPanelStatic embed.FS

//go:embed admin/templates/*
var AdminPanelTemplates embed.FS

//go:embed install/oauthseeker.systemd
var SystemdServiceFile []byte

//go:embed install/oauthseeker.env
var EnvironmentFile []byte
