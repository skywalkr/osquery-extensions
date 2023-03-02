package driveinfo

import (
	"encoding/json"
	"testing"
)

var jsontestdata []byte
var objtestdata map[string]interface{}

func TestGetConfig(t *testing.T) {
	result, err := GetConfig()

	if err != nil {
		t.Fatal("Failed to get path: ", err)
	}
	if result != "testing" {
		t.Fatalf(`Expected name {testing} got {%v}`, result)
	}
}

func TestGetJson(t *testing.T) {
	result, err := GetJson("testing")
	if err != nil {
		t.Fatal("Failed to read json test data: ", err)
	}
	if !json.Valid(result) {
		t.Fatal("Json test data is not valid")
	}
	jsontestdata = result
}

func TestGetData(t *testing.T) {
	result, err := GetData(jsontestdata)
	if err != nil {
		t.Fatal("Failed to parse JSON to obj: ", err)
	}
	objtestdata = result
}

func TestGetDrives(t *testing.T) {
	expectedcount := 15

	drives := GetDrives(objtestdata)

	if len(drives) != expectedcount {
		t.Fatal("Unexpected number of drives found: ", err)
	}
}
