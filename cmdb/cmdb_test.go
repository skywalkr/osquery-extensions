package cmdb

import (
	"osquery-extensions/config"
	"testing"
)

func TestTableColumns(t *testing.T) {
	conf := config.Config{}

	err := conf.Parse("../osquery-extensions.conf")

	if err != nil {
		t.Errorf("Error loading config %v: %v", "osquery-extensions.conf", err)
	}

	Initialize(&conf)
	c := TableColumns()

	if len(c) != 3 {
		t.Fatalf(`Expected {3} columns, got {%v}`, len(c))
	}
}
