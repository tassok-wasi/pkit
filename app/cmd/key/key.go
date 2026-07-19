package key

type KeyCmd struct {
	List    ListCmd    `cmd:"" help:""`
	Read    ReadCmd    `cmd:"" help:""`
	Verify  VerifyCmd  `cmd:"" help:""`
	Inspect InspectCmd `cmd:"" help:""`
}
