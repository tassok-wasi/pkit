package key

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"strings"
)

type InspectCmd struct {
	Name     string `name:"key-name" aliases:"key" required:"" help:"Name of the Key Pair."`
	Validate bool   `name:"validate" short:"v" help:"Verify the mathematical integrity and validity of the private key."`
}

func (ic *InspectCmd) Run(ctx context.Context, query base.Querier) error {
	key, err := query.GetKeyByName(ctx, ic.Name)
	if err != nil {
		return fmt.Errorf("failed to get Key: %w", err)
	}

	privateKey, publicKey, err := utils.ParseKeys([]byte(key.PrivateKeyPem), []byte(key.PublicKeyPem))
	if err != nil {
		return err
	}

	fmt.Printf("Key Inspection Report — %s\n", ic.Name)
	fmt.Println(strings.Repeat("─", 50))

	ic.inspectPrivateKey(privateKey, ic.Validate)

	fmt.Println(strings.Repeat("─", 50))

	ic.inspectPublicKey(publicKey, ic.Validate)

	fmt.Println(strings.Repeat("─", 50))

	return nil
}

func (ic *InspectCmd) inspectPrivateKey(key any, validate bool) {
	fmt.Println("  PRIVATE KEY")
	switch k := key.(type) {
	case *rsa.PrivateKey:
		fmt.Println("  \u2022 Algorithm            : RSA")
		fmt.Printf("  \u2022 Modulus Size         : %d-bit\n", k.Size()*8)
		fmt.Printf("  \u2022 Public Exponent (e)  : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  \u2022 Modulus Fingerprint  : %s...\n", utils.TruncateHex(k.N.Bytes()))
		fmt.Printf("  \u2022 Prime P Size         : %d bits\n", len(k.Primes[0].Bytes())*8)
		fmt.Printf("  \u2022 Prime Q Size         : %d bits\n", len(k.Primes[1].Bytes())*8)
		if validate {
			if err := k.Validate(); err != nil {
				fmt.Printf("  \u2022 Validation Failed  : %s\n", err)
			} else {
				fmt.Println("  \u2022 Validation Status  : Mathematically sound")
			}
		}

	case *ecdsa.PrivateKey:
		fmt.Println("  \u2022 Algorithm            : ECDSA")
		fmt.Printf("  \u2022 Curve                : %s\n", k.Params().Name)
		fmt.Printf("  \u2022 Order (N)            : %s...\n", utils.TruncateHex(k.Params().N.Bytes()))
		fmt.Println("  \u2022 Private Scalar (D)   : [hidden]")
		if validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  \u2022 Validation Status  : Curve point valid")
			} else {
				fmt.Printf("  \u2022 Validation Failed  : %s\n", err)
			}
		}

	case ed25519.PrivateKey:
		fmt.Println("  \u2022 Algorithm            : Ed25519")
		fmt.Printf("  \u2022 Seed                 : %s...\n", utils.TruncateHex(k.Seed()))
		fmt.Printf("  \u2022 Public Key (derived) : %s\n", hex.EncodeToString(k.Public().(ed25519.PublicKey)))

	default:
		fmt.Printf("  Unknown type       : %T\n", k)
	}
}

func (ic *InspectCmd) inspectPublicKey(key any, validate bool) {
	fmt.Println("PUBLIC KEY")
	switch k := key.(type) {
	case *rsa.PublicKey:
		fmt.Println("  \u2022 Algorithm            : RSA")
		fmt.Printf("  \u2022 Modulus Size         : %d-bit\n", k.Size()*8)
		fmt.Printf("  \u2022 Public Exponent (e)  : %d (0x%x)\n", k.E, k.E)
		fmt.Printf("  \u2022 Modulus Fingerprint  : %s...\n", utils.TruncateHex(k.N.Bytes()))

	case *ecdsa.PublicKey:
		fmt.Println("  \u2022 Algorithm            : ECDSA")
		fmt.Printf("  \u2022 Curve                : %s\n", k.Params().Name)
		pubBytes, _ := k.Bytes()
		fmt.Printf("  \u2022 Uncompressed Point   : %s...\n", utils.TruncateHex(pubBytes))
		if validate {
			if _, err := k.ECDH(); err == nil {
				fmt.Println("  \u2022 Validation Status  : Curve point valid")
			} else {
				fmt.Printf("  \u2022 Validation Failed  : %s\n", err)
			}
		}

	case ed25519.PublicKey:
		fmt.Println("  \u2022 Algorithm            : Ed25519")
		fmt.Printf("  \u2022 Public Point         : %s\n", hex.EncodeToString(k))
		if validate {
			fmt.Println("  \u2022 Validation Status  : Ed25519 public keys are always valid by construction")
		}

	default:
		fmt.Printf("  Unknown type       : %T\n", k)
	}
}
