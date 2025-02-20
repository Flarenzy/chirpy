-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
        gen_random_uuid(),
        NOW() at time zone 'utc',
        NOW() at time zone 'utc',
        $1
       ) RETURNING *;