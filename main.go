package main

import (
	"flag"
	"log"
	"os"
	"osquery-extensions/cmdb"
	"osquery-extensions/virtualization"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	socket := flag.String("socket", "", "Path to osquery socket file")
	_ = flag.Int("interval", 0, "Delay between connectivity checks")
	_ = flag.Int("timeout", 0, "Timeout for autoloaded extension")
	_ = flag.Bool("verbose", false, "")
	flag.Parse()

	if *socket == "" {
		log.Fatalf(`Usage: %s --socket SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("osquery-extensions", *socket)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	server.RegisterPlugin(table.NewPlugin("ci_info", cmdb.TableColumns(), cmdb.GenerateData))
	server.RegisterPlugin(table.NewPlugin("virtual_machines", virtualization.TableColumns(), virtualization.GenerateData))

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
