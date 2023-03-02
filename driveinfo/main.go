package driveinfo

import "github.com/osquery/osquery-go/plugin/table"

func TableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("controller"),
		table.TextColumn("encloser"),
		table.TextColumn("slot"),
		table.TextColumn("interface"),
		table.TextColumn("size"),
		table.TextColumn("model"),
		table.TextColumn("serial"),
		table.TextColumn("media"),
		table.TextColumn("state"),
	}
}
