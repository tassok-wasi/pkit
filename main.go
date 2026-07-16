package main

import (
	"certman/app/cmd"
	"log"
	"os"

	"github.com/alecthomas/kong"
)

type CLI struct {
	Registry *cmd.DataRegistry `kong:"-"`

	Write  cmd.WriteCmd  `cmd:"" help:"Writes Certificate and it's keys into a specified file structure."`
	Read   cmd.ReadCmd   `cmd:"" help:"Reads a Certificate or a specific Key from a file location"`
	Verify cmd.VerifyCmd `cmd:"" help:"Verifies Certificates and Key pairs"`
}

func main() {
	registry := &cmd.DataRegistry{}

	cli := CLI{Registry: registry}

	ctx := kong.Parse(&cli, kong.Name("certman"), kong.Description("A Certificate Management Toolkit"), kong.Bind(registry))

	err := ctx.Run()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
