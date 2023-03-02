package cmdb

import (
	"os"
	"path"
	"strings"
	"testing"
)

func TestPath(t *testing.T) {
	exPath, err := os.Executable()

	if err != nil {
		t.Fatal("Failed to get executable: ", err)
	}

	t.Log(strings.Replace(exPath, path.Ext(exPath), ".dat", 1))
}

func TestParseFile(t *testing.T) {
	result, err := parseFile("osquery.meta")

	if err != nil {
		t.Fatal("Failed to parse json: ", err)
	}

	if result["name"] != "test-server-1" {
		t.Fatalf(`Expected name {test} got {%v}`, result["name"])
	}
}
