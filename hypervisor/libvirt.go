//go:build linux

package hypervisor

import (
	"context"
	"encoding/xml"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/osquery/osquery-go/plugin/table"
)

var re = regexp.MustCompile(`\s(\d+|-)(?:\s+)(\S+)?(?:\s+)(\S+(?: \S+)?)`)

func countDisks(disks []Disk) int {
	var i = 0

	for _, d := range disks {
		if d.Device == "disk" {
			i++
		}
	}

	return i
}

func getVmState(vmName string, matches [][]string) string {
	var state string

	for _, match := range matches {
		if match[2] == vmName {
			state = match[3]
		}
	}

	switch state {
	case "idle":
		return "Idle"
	case "crashed":
		return "Error"
	case "paused":
		return "Paused"
	case "suspended":
		return "Suspended"
	case "running":
		return "Powered On"
	case "shut off":
		return "Powered Off"
	case "in shutdown":
		return "Shutting Down"
	default:
		return ""
	}
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var results []map[string]string

	path, err := exec.LookPath("virsh")

	if err != nil {
		return nil, err
	}

	// Get a list and state of vm's
	data, err := exec.Command(path, "list", "--all").Output()

	if err != nil {
		return nil, err
	}

	matches := re.FindAllStringSubmatch(string(data), -1)

	// Get xml configuration for all vm's
	data, err = exec.Command("/bin/sh", "-c", "echo \"<domains>\"; for vm in $(virsh list --all --name); do virsh dumpxml \"$vm\"; done; echo \"</domains>\";").Output()

	if err != nil {
		return nil, err
	}

	var domains Domains
	err = xml.Unmarshal(data, &domains)

	if err != nil {
		return nil, err
	}

	for _, domain := range domains.Domains {
		state := getVmState(domain.Name, matches)

		results = append(results, map[string]string{
			"type":   "KVM",
			"uuid":   domain.Id,
			"name":   domain.Name,
			"state":  state,
			"cpus":   strconv.Itoa(domain.Cpus),
			"disks":  strconv.Itoa(countDisks(domain.Devices.Disks)),
			"memory": strconv.FormatInt(domain.Memory*1024, 10),
			"nics":   strconv.Itoa(len(domain.Devices.Interfaces)),
		})
	}

	return results, nil
}

type Domains struct {
	XMLName xml.Name `xml:"domains"`
	Domains []Domain `xml:"domain"`
}

type Domain struct {
	XMLName xml.Name `xml:"domain"`
	Id      string   `xml:"uuid"`
	Name    string   `xml:"name"`
	Cpus    int      `xml:"vcpu"`
	Memory  int64    `xml:"memory"`

	Devices struct {
		XMLName     xml.Name     `xml:"devices"`
		Disks       []Disk       `xml:"disk"`
		Controllers []Controller `xml:"controller"`
		Interfaces  []Interface  `xml:"interface"`
	}
}

type Controller struct {
	Model string `xml:"model,attr"`
	Type  string `xml:"type,attr"`
}

type Disk struct {
	Device string `xml:"device,attr"`
	Type   string `xml:"type,attr"`
}

type Interface struct {
	Type string `xml:"type,attr"`
}
