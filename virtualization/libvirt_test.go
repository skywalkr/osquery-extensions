//go:build linux

package virtualization

import (
	"encoding/xml"
	"os"
	"testing"
)

func TestVirshRx(t *testing.T) {
	data, _ := os.ReadFile("./virsh.txt")

	matches := re.FindAllStringSubmatch(string(data), -1)

	if len(matches) != 8 {
		t.Fatalf(`Expected {8} got {%v} virtual machine(s)`, len(matches))
	}
}

func TestParseDomain(t *testing.T) {
	data, _ := os.ReadFile("./domains.xml")

	var domains Domains
	err := xml.Unmarshal(data, &domains)

	if err != nil {
		t.Fatal("Failed to parse xml: ", err)
	}

	if len(domains.Domains) != 2 {
		t.Fatalf(`Expected {2} got {%v} domain(s)`, len(domains.Domains))
	}

	if domains.Domains[0].Id != "d9bdebd7-40c6-4b40-b4b8-b7c19e2a9ca8" {
		t.Fatalf(`Expected id {d9bdebd7-40c6-4b40-b4b8-b7c19e2a9ca8} got {%v}`, domains.Domains[0].Id)
	}

	if len(domains.Domains[0].Devices.Disks) != 2 {
		t.Fatalf(`Expected {2} got {%v} disk(s)`, len(domains.Domains[0].Devices.Disks))
	}

	if len(domains.Domains[0].Devices.Controllers) != 18 {
		t.Fatalf(`Expected {18} got {%v} disk(s)`, len(domains.Domains[0].Devices.Controllers))
	}

	if len(domains.Domains[0].Devices.Interfaces) != 1 {
		t.Fatalf(`Expected {1} got {%v} disk(s)`, len(domains.Domains[0].Devices.Interfaces))
	}
}
