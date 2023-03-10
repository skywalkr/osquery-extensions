//go:build linux

package driveinfo

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"regexp"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/spf13/viper"
)

var drivere = regexp.MustCompile(`^Drive (/\S+?/\S+?/\S+?)$`)
var EIDSltre = regexp.MustCompile(`(\d+):(\d+)`)
var PERCPATH = "/opt/nf-observability/bin/perccli64"

// var path string
var err error

func GetConfig() (string, error) {
	viper.AutomaticEnv()
	path := viper.GetString("PERCPATH")

	if len(path) == 0 {
		viper.SetConfigName("driveinfo")
		viper.SetConfigType("env")
		viper.AddConfigPath("/etc/osquery/")
		viper.AddConfigPath(".")
		if err = viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); ok {
				log.Output(1, "Config file or environment variable not found")
				path, err = exec.LookPath("storcli")
				if err != nil {
					log.Output(1, err.Error())
				}
			} else {
				log.Output(1, "Config file was found but another error was produced")
				return "", err
			}
		}
		if len(path) == 0 {
			viper.SetDefault("PERCPATH", PERCPATH)
			path = viper.GetString("PERCPATH")
			log.Output(1, "Using path: "+path)
		} else {
			log.Output(1, "Using binary found in $PATH: "+path)
		}
	}
	return path, nil
}

func GetJson(path string) (jsondata []byte, err error) {
	if path == "testing" {
		jsondata, err = os.ReadFile("storcli.json")
		if err != nil {
			return nil, err
		}
	} else {
		jsondata, err = exec.Command(path, "/cALL/eALL/sALL", "show", "all", "j").Output()
		if err != nil {
			return nil, err
		}
	}
	return jsondata, nil
}

func GetData(jsondata []byte) (map[string]interface{}, error) {
	var obj map[string]interface{}

	err = json.Unmarshal([]byte(jsondata), &obj)
	if err != nil {
		return nil, err
	}

	data := obj["Controllers"].([]interface{})[0].(map[string]interface{})["Response Data"].(map[string]interface{})

	return data, nil
}

func GetDrives(data map[string]interface{}) (drives []map[string]string) {
	for k, v := range data {
		match := drivere.FindStringSubmatch(k)
		if len(match) != 0 {
			drive := v.([]interface{})[0]
			drivedetails := data["Drive "+match[1]+" - Detailed Information"]
			drive.(map[string]interface{})["SN"] = drivedetails.(map[string]interface{})["Drive "+match[1]+" Device attributes"].(map[string]interface{})["SN"]
			eidslt := EIDSltre.FindStringSubmatch(drive.(map[string]interface{})["EID:Slt"].(string))
			drives = append(drives, map[string]string{
				"controller": "0",
				"encloser":   eidslt[1],
				"slot":       eidslt[2],
				"model":      drive.(map[string]interface{})["Model"].(string),
				"serial":     drive.(map[string]interface{})["SN"].(string),
				"interface":  drive.(map[string]interface{})["Intf"].(string),
				"media":      drive.(map[string]interface{})["Med"].(string),
				"size":       drive.(map[string]interface{})["Size"].(string),
				"state":      drive.(map[string]interface{})["State"].(string),
			})
		}
	}
	return drives
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	path, err := GetConfig()
	if err != nil {
		return nil, err
	}

	// Get a list and state of drives
	jsondata, err := GetJson(path)
	if err != nil {
		return nil, err
	}

	data, err := GetData(jsondata)
	if err != nil {
		return nil, err
	}

	drives := GetDrives(data)

	return drives, nil
}
