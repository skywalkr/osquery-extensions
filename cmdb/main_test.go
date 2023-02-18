package cmdb

import (
	"testing"
)

func TestParseFile(t *testing.T) {
	result, err := parseFile("osquery.meta")

	if err != nil {
		t.Fatal("Failed to parse json: ", err)
	}

	if result["name"] != "test-server-1" {
		t.Fatalf(`Expected name {test} got {%v}`, result["name"])
	}
}
