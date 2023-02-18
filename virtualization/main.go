package virtualization

import "github.com/osquery/osquery-go/plugin/table"

func TableColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("uuid"),
		table.TextColumn("name"),
		table.TextColumn("state"),
		table.TextColumn("type"),
		table.IntegerColumn("cpus"),
		table.IntegerColumn("nics"),
		table.IntegerColumn("disks"),
		table.IntegerColumn("disks_size"),
		table.BigIntColumn("memory"),
	}
}
