package cmdb

import (
	"context"
	"fmt"
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
			s := fmt.Sprintf("cmdb_%s", key)
			result[s] = val
		}
	}

	return []map[string]string{result}, nil
}

func TableColumns() []table.ColumnDefinition {
	var columns []table.ColumnDefinition

	for key := range conf.CMDB {
		s := fmt.Sprintf("cmdb_%s", key)
		columns = append(columns, table.TextColumn(s))
	}

	return columns
}
