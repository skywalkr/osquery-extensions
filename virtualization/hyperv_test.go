//go:build windows

package virtualization

import (
	"encoding/json"
	"os"
	"testing"
)

func TestParseVirtualMachine(t *testing.T) {
	data, _ := os.ReadFile("./vms.json")

	var vms []VirtualMachine
	err := json.Unmarshal(data, &vms)

	if err != nil {
		t.Fatal("Failed to parse json: ", err)
	}

	if len(vms) != 2 {
		t.Fatalf(`Expected {2} got {%v} virtual machine(s)`, len(vms))
	}

	if vms[0].Id != "f2b80bd6-15b5-434e-b360-c99d6612effa" {
		t.Fatalf(`Expected id {f2b80bd6-15b5-434e-b360-c99d6612effa} got {%v} `, vms[0].Id)
	}
}
