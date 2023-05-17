package ipmi

import (
        "context"
        "os/exec"
        "strings"

        "github.com/osquery/osquery-go/plugin/table"
)

func TableColumns() []table.ColumnDefinition {
        return []table.ColumnDefinition{
                table.TextColumn("ipmi_ip"),
                table.TextColumn("ipmi_mac"),
                table.TextColumn("ipmi_subnet_mask"),
                table.TextColumn("ipmi_snmp_community"),
                table.TextColumn("ipmi_default_gateway"),
                table.TextColumn("ipmi_default_gateway_mac"),
        }
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
        cmd := exec.Command("ipmitool", "lan", "print")
        out, err := cmd.Output()
        if err != nil {
                return nil, err
        }

        ipmiIP, ipmiMAC, ipmiSubnetMask, ipmiSNMPCommunity, ipmiGateway, ipmiGatewayMAC, err := parseIPMIOutput(out)
        if err != nil {
                return nil, err
        }

        rows := []map[string]string{
                {
                        "ipmi_ip":             ipmiIP,
                        "ipmi_mac":            ipmiMAC,
                        "ipmi_subnet_mask":      ipmiSubnetMask,
                        "ipmi_snmp_community": ipmiSNMPCommunity,
                        "ipmi_default_gateway": ipmiGateway,
                        "ipmi_default_gateway_mac": ipmiGatewayMAC,
                },
        }

        return rows, nil
}

func parseIPMIOutput(out []byte) (string, string, string, string, string, string, error) {
        var ipmiIP, ipmiMAC, ipmiSubnetMask, ipmiSNMPCommunity, ipmiGateway, ipmiGatewayMAC string

        lines := strings.Split(string(out), "\n")
        for _, line := range lines {
                if strings.HasPrefix(line, "IP Address") {
                        fields := strings.Fields(line)
                        if len(fields) < 4 {
                                continue
                        }
                        ipmiIP = fields[3]
                } else if strings.HasPrefix(line, "MAC Address") {
                        fields := strings.Fields(line)
                        if len(fields) < 4 {
                                continue
                        }
                        ipmiMAC = fields[3]
                } else if strings.HasPrefix(line, "Subnet Mask") {
                        fields := strings.SplitN(line, ":", 2)
                        if len(fields) < 2 {
                                continue
                        }
                        ipmiSubnetMask = strings.TrimSpace(fields[1])
                } else if strings.HasPrefix(line, "SNMP Community String") {
                        fields := strings.SplitN(line, ":", 2)
                        if len(fields) < 2 {
                                continue
                        }
                        ipmiSNMPCommunity = strings.TrimSpace(fields[1])
                } else if strings.HasPrefix(line, "Default Gateway IP") {
                        fields := strings.SplitN(line, ":", 2)
                        if len(fields) < 2 {
                                continue
                        }
                        ipmiGateway = strings.TrimSpace(fields[1])
                }else if strings.HasPrefix(line, "Default Gateway MAC") {
                        fields := strings.SplitN(line, ":", 2)
                        if len(fields) < 2 {
                                continue
                        }
                        ipmiGatewayMAC = strings.TrimSpace(fields[1])
                }


        }

        return ipmiIP, ipmiMAC, ipmiSubnetMask, ipmiSNMPCommunity, ipmiGateway, ipmiGatewayMAC, nil
}

