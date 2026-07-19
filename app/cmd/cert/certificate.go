package cert

import "certman/app/cmd/cert/gen"

type CertificateCmd struct {
	Generate gen.GenerateCmd `cmd:"" help:""`
	List     ListCmd         `cmd:"" help:""`
	Read     ReadCmd         `cmd:"" help:""`
	Verify   VerifyCmd       `cmd:"" help:""`
	Inspect  InspectCmd      `cmd:"" help:""`
	Revoke   RevokeCmd       `cmd:"" help:""`
	Export   ExportCmd       `cmd:"" help:""`
}
