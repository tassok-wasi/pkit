-- name: CreateKey :one
INSERT INTO keys (id, key_type, public_key, private_key)
VALUES (sqlc.arg('id'), sqlc.arg('key_type'), sqlc.arg('public_key'), sqlc.arg('private_key'))
RETURNING *;

-- name: ListKeys :many
SELECT id, key_type, public_key, private_key, created_at
FROM keys
ORDER BY created_at DESC;

-- name: CreateCertificate :one
INSERT INTO certificates (id, key_id, serial_number, cert_type, subject, issuer, not_before, not_after, pem_content)
VALUES (sqlc.arg('id'), sqlc.arg('key_id'), sqlc.arg('serial_number'), sqlc.arg('cert_type'), sqlc.arg('subject'),
		sqlc.arg('issuer'), sqlc.arg('not_before'), sqlc.arg('not_after'), sqlc.arg('pem_content'))
RETURNING *;

-- name: ListCertificates :many
SELECT id, key_id, serial_number, cert_type, subject, issuer, not_before, not_after, pem_content, created_at
FROM certificates
ORDER BY created_at DESC;
