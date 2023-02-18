//go:build windows

package virtualization

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
)

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	path, err := exec.LookPath("powershell")

	if err != nil {
		return nil, err
	}

	out, err := exec.Command(path, "get-vm | convertto-json").Output()

	if err != nil {
		return nil, err
	}

	var vms []VirtualMachine
	err = json.Unmarshal(out, &vms)

	if err != nil {
		return nil, err
	}

	var results []map[string]string

	for _, vm := range vms {
		var state = "Unknown"

		switch vm.State {
		case 2:
			state = "Powered On"
		case 3:
			state = "Powered Off"
		case 6:
			state = "Suspended"
		case 9:
			state = "Paused"
		case 32786:
			state = "Crashed"
		case 32789:
			state = "Blocked"
		}

		results = append(results, map[string]string{
			"uuid":   vm.Id,
			"name":   vm.Name,
			"state":  state,
			"type":   "HYPERV",
			"cpus":   strconv.Itoa(vm.ProcessorCount),
			"disks":  strconv.Itoa(len(vm.HardDrives)),
			"memory": strconv.FormatInt(vm.MemoryMinimum, 10),
			"nics":   strconv.Itoa(len(vm.NetworkAdapters)),
		})
	}

	return results, nil
}

type VirtualMachine struct {
	Id              string
	Name            string
	State           int
	MemoryAssigned  int64
	MemoryMinimum   int64
	ProcessorCount  int
	HardDrives      []string
	NetworkAdapters []string
}
