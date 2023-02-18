package main

import (
	"flag"
	"log"
	"os"
	"osquery-extensions/cmdb"
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

	server.RegisterPlugin(table.NewPlugin("ci_info", cmdb.TableColumns(), cmdb.GenerateData))
	server.RegisterPlugin(table.NewPlugin("virtual_machines", virtualization.TableColumns(), virtualization.GenerateData))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
