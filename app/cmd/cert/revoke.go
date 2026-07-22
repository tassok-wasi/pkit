package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"database/sql"
	"fmt"
	"time"
)

type RevokeCmd struct {
	ID     int64  `arg:"" help:"Certificate ID"`
	Reason string `name:"reason" short:"r" required:"" enum:"unspecified,key-compromise,ca-compromise,affiliation-changed,superseded,cessation-of-operation,certificate-hold,remove-from-crl,privilege-withdrawn,a-a-compromise" help:"Reason for revoking the Certificate."`
}

func (rc *RevokeCmd) Run(ctx context.Context, query base.Querier) error {
	dbCert, err := query.GetCertificateByID(ctx, rc.ID)
	if err != nil {
		return fmt.Errorf("failed to fetch certificate from DB: %w", err)
	}

	if dbCert.IsRevoked.Int64 == 1 {
		fmt.Println("Certificate is already Revoked!")
		return nil
	}

	revReasonCode, err := utils.ParseRevocationReason(rc.Reason)
	if err != nil {
		return err
	}

	_, err = query.RevokeCertificate(ctx, base.RevokeCertificateParams{
		IsRevoked:        sql.NullInt64{Int64: 1, Valid: true},
		RevocationTime:   sql.NullTime{Time: time.Now(), Valid: true},
		RevocationReason: sql.NullInt64{Int64: int64(revReasonCode), Valid: true},
		SerialNumber:     dbCert.SerialNumber,
	})
	if err != nil {
		return fmt.Errorf("failed to Revoke Certificate: %w", err)
	}

	fmt.Println("Successfully Revoked Certificate.")

	return nil
}
