package config

import "testing"

func TestLoadConfig(t *testing.T) {
	conf := Config{}

	err := conf.Parse("../osquery-extensions.conf")

	if err != nil {
		t.Errorf("Error loading config %v: %v", "osquery-extensions.conf", err)
	}
}
