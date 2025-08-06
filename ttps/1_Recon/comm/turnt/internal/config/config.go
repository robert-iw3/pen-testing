package config

import (
	"os"

	"github.com/pion/webrtc/v3"
	"gopkg.in/yaml.v2"
)

type Config struct {
	ICEServers []webrtc.ICEServer `yaml:"ice_servers"`
}

func LoadConfig(path string) (*Config, error) {
	var config Config

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
