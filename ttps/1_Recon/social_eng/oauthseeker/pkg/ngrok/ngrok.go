package ngrok

import (
	"context"
	"net"

	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

func CreateTunnel(domain, token string) (net.Listener, error) {
	return ngrok.Listen(context.Background(),
		config.HTTPEndpoint(
			config.WithDomain(domain),
		),
		ngrok.WithAuthtoken(token),
	)
}
