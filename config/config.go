package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	CMDB map[string]interface{}
}

func (conf *Config) Parse(confFile string) (err error) {
	data, err := os.ReadFile(confFile)

	if err != nil {
		return fmt.Errorf("error reading config file: %s", err)
	}

	if err = json.Unmarshal(data, &conf); err != nil {
		return fmt.Errorf("error parsing config file: %s", err)
	}

	return nil
}
