package cmdb

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

var re = regexp.MustCompile(`(?m)^([_A-Z]+)=(.*)$`)

func parseFile(filePath string) (map[string]string, error) {
	data, err := os.ReadFile(filePath)

	if err != nil {
		return nil, err
	}

	result := make(map[string]string)
	matches := re.FindAllStringSubmatch(string(data), -1)

	for _, match := range matches {
		// TrimSuffix for windowz :|
		result[strings.ToLower(match[1])] = strings.TrimSpace(match[2])
	}

	return result, nil
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	exPath, _ := os.Executable()

	// Move this to a conditional path in the future via where clause
	result, err := parseFile(path.Join(filepath.Dir(exPath), "osquery.meta"))

	if err != nil {
		return nil, err
	}

	return []map[string]string{result}, nil
}

func TableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.TextColumn("used_for"),
		table.TextColumn("cmdb_group"),
		table.TextColumn("managedby_group"),
	}
}
