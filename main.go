package main

import (
	"flag"
	"log"
	"os"
	"osquery-extensions/cmdb"
	"osquery-extensions/config"
	"osquery-extensions/driveinfo"
	"osquery-extensions/ipmi"
	"osquery-extensions/virtualization"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	conf     = &config.Config{}
	socket   = flag.String("socket", "", "Path to osquery socket file")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
	_        = flag.Bool("verbose", false, "")
)

func main() {
	flag.Parse()

	exPath, _ := os.Executable()
	err := conf.Parse(strings.Replace(exPath, path.Ext(exPath), ".conf", 1))

	if err != nil {
		log.Fatalf("Error loading config: %s\n", err)
	}

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

	cmdb.Initialize(conf)

	server.RegisterPlugin(table.NewPlugin("ci_info", cmdb.TableColumns(), cmdb.GenerateData))
	server.RegisterPlugin(table.NewPlugin("disk_information", driveinfo.TableColumns(), driveinfo.GenerateData))
	server.RegisterPlugin(table.NewPlugin("virtual_machines", virtualization.TableColumns(), virtualization.GenerateData))

	if runtime.GOOS == "linux" {
		server.RegisterPlugin(table.NewPlugin("ipmi", ipmi.TableColumns(), ipmi.GenerateData))
	}

	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
