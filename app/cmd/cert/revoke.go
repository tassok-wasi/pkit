package cert

import (
	"certman/app/utils"
	"certman/db/base"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type RevokeCmd struct {
	SerialNumber string `name:"sn" help:"Serial Number of the Certificate. Either one can be selected and one must be selected."`
	CommonName   string `name:"cn" help:"Common Name of the Certificate. Either one can be selected and one must be selected."`
	Reason       string `name:"reason" short:"r" required:"" enum:"unspecified,key-compromiseca-compromise,affiliation-changed,superseded,cessation-of-operation,certificate-hold,remove-from-crl,privilege-withdrawn,a-a-compromise" help:"Reason for revoking the Certificate."`
}

func (rc *RevokeCmd) Run(ctx context.Context, query base.Querier) error {
	var dbCert base.Certificate
	var err error
	empty := sql.NullInt64{Int64: 0, Valid: false}

	if rc.SerialNumber != "" && rc.CommonName == "" {
		dbCert, err = query.GetCertificateBySN(ctx, rc.SerialNumber)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else if rc.SerialNumber == "" && rc.CommonName != "" {
		dbCert, err = query.GetCertificateByCN(ctx, rc.CommonName)
		if err != nil {
			return fmt.Errorf("failed to get Certificate: %w", err)
		}
	} else {
		return errors.New("exactly one flag (--sn or --cn) must be provided")
	}

	if dbCert.IsRevoked != empty {
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
	})
	if err != nil {
		return fmt.Errorf("could not Revoke Certificate: %w", err)
	}

	fmt.Println("Successfully Revoked Certificate.")

	return nil
}
