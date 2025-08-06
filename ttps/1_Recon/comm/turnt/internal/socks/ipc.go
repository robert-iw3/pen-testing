package socks

type connectionDetails struct {
	NetworkType string `json:"network_type"`
	TargetAddr  string `json:"target_addr"`
}

// RemotePortForwardRequest represents a request to start or stop a remote port forward
type RemotePortForwardRequest struct {
	Type string `json:"type"`
	GUID string `json:"guid"`
	Port string `json:"port"` // The port to bind to on the relay (e.g. "8080")
}

// RemotePortForwardResponse represents a response to a remote port forward request
type RemotePortForwardResponse struct {
	Type    string `json:"type"`
	GUID    string `json:"guid"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}
