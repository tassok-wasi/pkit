-- name: CreateKeyPair :one
INSERT INTO keys (
    name,
    algorithm,
    private_key_pem,
    public_key_pem
) VALUES (
    sqlc.arg('name'),
    sqlc.arg('algorithm'),
    sqlc.arg('private_key_pem'),
    sqlc.arg('public_key_pem')
)
RETURNING *;

-- name: CreateCertificate :one
INSERT INTO certificates (
    serial_number,
    common_name,
    type,
    key_id,
    issuer_serial_number,
    skid,
    akid,
    status,
    not_before,
    not_after,
    certificate_pem
) VALUES (
    sqlc.arg('serial_number'),
    sqlc.arg('common_name'),
    sqlc.arg('type'),
    sqlc.arg('key_id'),
    sqlc.arg('issuer_serial_number'),
    sqlc.arg('skid'),
    sqlc.arg('akid'),
    sqlc.arg('status'),
    sqlc.arg('not_before'),
    sqlc.arg('not_after'),
    sqlc.arg('certificate_pem')
)
RETURNING *;

-- name: ListCertificates :many
SELECT id, serial_number, common_name, type, status, not_after, is_revoked
FROM certificates
WHERE
    (CAST(sqlc.narg('status') AS TEXT) IS NULL OR status = CAST(sqlc.narg('status') AS TEXT))
    AND (CAST(sqlc.narg('type') AS TEXT) IS NULL OR type = CAST(sqlc.narg('type') AS TEXT))
ORDER BY id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListAllCertificates :many
SELECT id, serial_number, common_name, type, status, not_after, is_revoked
FROM certificates
WHERE
    (CAST(sqlc.narg('status') AS TEXT) IS NULL OR status = CAST(sqlc.narg('status') AS TEXT))
    AND (CAST(sqlc.narg('type') AS TEXT) IS NULL OR type = CAST(sqlc.narg('type') AS TEXT))
ORDER BY id ASC;

-- name: ListKeys :many
SELECT id, name, algorithm, created_at
FROM keys
ORDER BY id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListAllKeys :many
SELECT id, name, algorithm, created_at
FROM keys
ORDER BY id ASC;

-- name: GetKeyByID :one
SELECT * FROM keys WHERE id = sqlc.arg('id');

-- name: GetKeyByName :one
SELECT * FROM keys WHERE name = sqlc.arg('name');

-- name: GetCertificateByID :one
SELECT * FROM certificates WHERE id = sqlc.arg('id');

-- name: GetCertificateBySN :one
SELECT * FROM certificates WHERE serial_number = sqlc.arg('serial_number');

-- name: GetCertificateByCN :one
SELECT * FROM certificates WHERE common_name = sqlc.arg('common_name');

-- name: GetCertificateBySKID :one
SELECT * FROM certificates WHERE skid = sqlc.arg('skid');

-- name: GetCertificateSerialNumberByID :one
SELECT serial_number FROM certificates WHERE id = sqlc.arg('id');


-- name: UpdateCertificate :one
UPDATE certificates
SET
  common_name = COALESCE(sqlc.narg('common_name'), common_name),
  type = COALESCE(sqlc.narg('type'), type),
  key_id = COALESCE(sqlc.narg('key_id'), key_id),
  issuer_serial_number = COALESCE(sqlc.narg('issuer_serial_number'), issuer_serial_number),
  skid = COALESCE(sqlc.narg('skid'), skid),
  akid = COALESCE(sqlc.narg('akid'), akid),
  status = COALESCE(sqlc.narg('status'), status),
  not_before = COALESCE(sqlc.narg('not_before'), not_before),
  not_after = COALESCE(sqlc.narg('not_after'), not_after),
  certificate_pem = COALESCE(sqlc.narg('certificate_pem'), certificate_pem)
WHERE serial_number = sqlc.arg('serial_number')
RETURNING *;

-- name: RevokeCertificate :one
UPDATE certificates
SET
    is_revoked = COALESCE(sqlc.arg('is_revoked'), is_revoked),
    revocation_reason = COALESCE(sqlc.arg('revocation_reason'), revocation_reason),
    revocation_time = COALESCE(sqlc.arg('revocation_time'), revocation_time),
    status = COALESCE(sqlc.arg('status'), status)
WHERE serial_number = sqlc.arg('serial_number')
RETURNING *;

-- name: ListRevokedCertificates :many
SELECT * FROM certificates
WHERE
    issuer_serial_number = sqlc.arg('issuer_serial_number')
    AND is_revoked = 1
ORDER BY id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListAllRevokedCertificates :many
SELECT * FROM certificates
WHERE
    issuer_serial_number = sqlc.arg('issuer_serial_number')
    AND is_revoked = 1
ORDER BY id ASC;

-- name: CreateCRL :one
INSERT INTO crls (
    name,
    crl_number,
    issuer_id,
    this_update,
    next_update,
    crl_pem
) VALUES (
    sqlc.arg('name'),
    sqlc.arg('crl_number'),
    sqlc.arg('issuer_id'),
    sqlc.arg('this_update'),
    sqlc.arg('next_update'),
    sqlc.arg('crl_pem')
)
RETURNING *;

-- name: GetLatestCRL :one
SELECT
    name,
    crl_number,
    issuer_id,
    this_update,
    next_update,
    crl_pem
FROM crls
WHERE issuer_id = sqlc.arg('issuer_id')
ORDER BY created_at DESC
LIMIT 1;

-- name: ListCRLs :many
SELECT * FROM crls
WHERE issuer_id = sqlc.arg('issuer_id')
ORDER BY id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListAllCRLs :many
SELECT * FROM crls
WHERE issuer_id = sqlc.arg('issuer_id')
ORDER BY id ASC;


-- name: GetCRLByID :one
SELECT * FROM crls WHERE id = sqlc.arg('id');

-- name: CreateCSR :one
INSERT INTO csrs (
    common_name,
    key_id,
    status,
    csr_pem,
    certificate_id
) VALUES (
    sqlc.arg('common_name'),
    sqlc.arg('key_id'),
    sqlc.arg('status'),
    sqlc.arg('csr_pem'),
    sqlc.arg('certificate_id')
)
RETURNING *;

-- name: ListCSRs :many
SELECT id, common_name, key_id, status, csr_pem, certificate_id
FROM csrs
WHERE (CAST(sqlc.narg('status') AS TEXT) IS NULL OR status = CAST(sqlc.narg('status') AS TEXT))
ORDER BY id ASC
LIMIT sqlc.arg('limit')
OFFSET sqlc.arg('offset');

-- name: ListAllCSRs :many
SELECT id, common_name, key_id, status, csr_pem, certificate_id
FROM csrs
WHERE (CAST(sqlc.narg('status') AS TEXT) IS NULL OR status = CAST(sqlc.narg('status') AS TEXT))
ORDER BY id ASC;

-- name: UpdateCSRStatus :exec
UPDATE csrs
SET status = sqlc.arg('status'), certificate_id = sqlc.arg('certificate_id')
WHERE common_name = sqlc.arg('common_name');

-- name: GetCSRByID :one
SELECT * FROM csrs WHERE id = sqlc.arg('id');
