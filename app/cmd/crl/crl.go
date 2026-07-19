package crl

type CrlCmd struct {
	Generate GenerateCmd `cmd:"" help:""`
	List     ListCmd     `cmd:"" help:""`
	Export   ExportCmd   `cmd:"" help:""`
}
