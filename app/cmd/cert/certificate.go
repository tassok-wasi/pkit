package cert

import (
	"certman/app/cmd/cert/exp"
	"certman/app/cmd/cert/gen"
)

type CertificateCmd struct {
	Generate gen.GenerateCmd `cmd:"" help:""`
	List     ListCmd         `cmd:"" help:""`
	Read     ReadCmd         `cmd:"" help:""`
	Inspect  InspectCmd      `cmd:"" help:""`
	Validate ValidateCmd     `cmd:"" help:""`
	Verify   VerifyCmd       `cmd:"" help:""`
	Diff     DiffCmd         `cmd:"" help:""`
	Revoke   RevokeCmd       `cmd:"" help:""`
	Rotate   RotateCmd       `cmd:"" help:""`
	Export   exp.ExportCmd   `cmd:"" help:""`
}
