//go:build windows

package driveinfo

import (
	"context"
	"errors"

	"github.com/osquery/osquery-go/plugin/table"
)

func GenerateData(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return nil, errors.New("driveinfo: not implemented on this platform")
}
