-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
        $1,
        NOW() at time zone 'utc',
        NOW() AT TIME ZONE 'utc',
        $2,
        NOW() AT TIME ZONE 'utc' + INTERVAL '60 days',
        NULL
       ) RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT refresh_tokens.*, users.* FROM refresh_tokens
INNER JOIN users ON users.id = refresh_tokens.user_id
WHERE token = $1;


-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW() AT TIME ZONE 'utc', updated_at = NOW() AT TIME ZONE 'utc'
WHERE token = $1;