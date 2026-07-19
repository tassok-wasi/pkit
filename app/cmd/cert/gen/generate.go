package gen

type GenerateCmd struct {
	CA   CACmd   `cmd:"" help:""`
	ICA  ICACmd  `cmd:"" help:""`
	Leaf LeafCmd `cmd:"" help:""`
}
