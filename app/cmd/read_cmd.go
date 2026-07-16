package cmd

import (
	"certman/app/utils"
	"fmt"
)

type ReadCmd struct {
	Cert ReadCertCmd `cmd:"" help:"Reads Certificate from file location and prints it to stdout"`
	Key  ReadKeyCmd  `cmd:"" help:"Reads Key from file location and prints it to stdout"`
}

type ReadCertCmd struct {
	Path string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.cert) format."`
}

func (rcc *ReadCertCmd) Run() error {
	cert, err := utils.ReadFile(rcc.Path)
	if err != nil {
		return fmt.Errorf("file does not contains valid certificate")
	}

	fmt.Println(string(cert))
	return nil
}

type ReadKeyCmd struct {
	Path string `name:"path" short:"p" required:"" type:"path" help:"Path to read a file. file must be in (.key,.pem) format."`
}

func (rkc *ReadKeyCmd) Run() error {
	key, err := utils.ReadFile(rkc.Path)
	if err != nil {
		return fmt.Errorf("file does not contains valid key")
	}

	fmt.Println(string(key))
	return nil
}
