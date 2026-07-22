package key

import (
	"certman/app/domain"
	"certman/app/utils"
	"certman/db/base"
	"context"
	"fmt"
)

type GenerateCmd struct {
	KeyType string `name:"type" required:"" enum:"rsa-2048,rsa-4096,ecdsa-224,ecdsa-256,ecdsa-384,ecdsa-521,ed25519" default:"ed25519" help:"Specifies the Key Algorithm."`
	Name    string `name:"name" required:"" help:"Name of the key Pair in the Database."`
}

func (gc *GenerateCmd) Run(ctx context.Context, query base.Querier) error {
	keyPair, err := domain.GetKey(domain.KeyType(gc.KeyType))
	if err != nil {
		return err
	}

	privBlobPem, pubPem, err := utils.ReturnPrivPubPem(keyPair.PrivateKey, keyPair.PublicKey)
	if err != nil {
		return err
	}

	_, err = query.CreateKeyPair(ctx, base.CreateKeyPairParams{
		Name:          gc.Name,
		Algorithm:     gc.KeyType,
		PrivateKeyPem: privBlobPem,
		PublicKeyPem:  pubPem,
	})
	if err != nil {
		return fmt.Errorf("failed to create Key Pair in DB: %w", err)
	}

	return nil
}
