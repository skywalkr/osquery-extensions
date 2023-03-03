package cmdb

import (
	"context"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

var (
	re = regexp.MustCompile(`(?m)^([_A-Z]+)=(.*)$`)
	fp = ""
)

func parseFile(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	result := map[string]string{"path": filePath}
	matches := re.FindAllStringSubmatch(string(data), -1)

	for _, match := range matches {
		// TrimSuffix for windowz :|
		result[strings.ToLower(match[1])] = strings.TrimSpace(match[2])
	}

	return result, nil
}

func Initialize(configFile string) {
	exPath, err := os.Executable()

	if err != nil {
		log.Fatalf("Error initializing CMDB plugin: %v", err)
	}

	fp = path.Join(path.Dir(configFile), strings.TrimSuffix(filepath.Base(exPath), path.Ext(exPath))+".dat")
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	var filePath string

	if len(queryContext.Constraints["path"].Constraints) == 0 {
		filePath = fp
	} else {
		filePath = queryContext.Constraints["path"].Constraints[0].Expression
	}

	result, err := parseFile(filePath)

	if err != nil {
		return nil, err
	}

	return []map[string]string{result}, nil
}

func TableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("path"),
		table.TextColumn("used_for"),
		table.TextColumn("cmdb_group"),
		table.TextColumn("managedby_group"),
	}
}
