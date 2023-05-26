package cmdb

import (
	"context"
	"osquery-extensions/config"

	"github.com/osquery/osquery-go/plugin/table"
)

var (
	conf *config.Config
)

func Initialize(c *config.Config) {
	conf = c
}

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	result := map[string]string{}

	for key, val := range conf.CMDB {
		switch val := val.(type) {
		case string:
			result[key] = val
		}
	}

	return []map[string]string{result}, nil
}

func TableColumns() []table.ColumnDefinition {
	var columns []table.ColumnDefinition

	for key := range conf.CMDB {
		columns = append(columns, table.TextColumn(key))
	}

	return columns
}
