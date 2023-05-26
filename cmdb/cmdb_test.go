package cmdb

import (
	"osquery-extensions/config"
	"strings"
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

	if !strings.HasPrefix(c[0].Name, "cmdb_") {
		t.Fatalf(`Expected column name to have prefix {cmdb_}, got {%v}`, c[0].Name)
	}
}
