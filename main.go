package main

import (
	"flag"
	"log"
	"os"
	"osquery-extensions/cmdb"
	"osquery-extensions/driveinfo"
	"osquery-extensions/virtualization"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to osquery socket file")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
	_        = flag.Bool("verbose", false, "")
)

func main() {
	flag.Parse()

	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"osquery-extensions",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	var addFlags = getOsqueryFlags(*socket)
	cmdb.Initialize(addFlags[0]["value"])

	server.RegisterPlugin(table.NewPlugin("ci_info", cmdb.TableColumns(), cmdb.GenerateData))
	server.RegisterPlugin(table.NewPlugin("disk_information", driveinfo.TableColumns(), driveinfo.GenerateData))
	server.RegisterPlugin(table.NewPlugin("virtual_machines", virtualization.TableColumns(), virtualization.GenerateData))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

func getOsqueryFlags(socket string) []map[string]string {
	client, err := osquery.NewClient(socket, 1*time.Second)

	if err != nil {
		log.Fatalf("Error creating Thrift client: %v", err)
	}

	defer client.Close()

	resp, err := client.Query("select * from osquery_flags where name in ('config_path');")
	if err != nil {
		log.Fatalf("Error communicating with osqueryd: %v", err)
	}
	if resp.Status.Code != 0 {
		log.Fatalf("osqueryd returned error: %s", resp.Status.Message)
	}

	return resp.Response
}
