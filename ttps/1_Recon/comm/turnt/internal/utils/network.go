package utils

import (
	"context"
	"fmt"
	"net"
	"time"
)

func DialTarget(networkType, targetAddr string) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = 10 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	return d.DialContext(ctx, networkType, targetAddr)
}

func ValidateNetworkType(networkType string) bool {
	return networkType == "tcp" || networkType == "udp"
}

func SplitAndVerifyPort(addr, transport string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid address format: %v", err)
	}

	_, err = net.LookupPort(transport, port)
	if err != nil {
		return "", fmt.Errorf("invalid port: %v", err)
	}

	return port, nil
}
