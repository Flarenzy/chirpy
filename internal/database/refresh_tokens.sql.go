// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: refresh_tokens.sql

package database

import (
	"context"
	"database/sql"
	"time"

	"github.com/google/uuid"
)

const createRefreshToken = `-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, created_at, updated_at, user_id, expires_at, revoked_at)
VALUES (
        $1,
        NOW() at time zone 'utc',
        NOW() AT TIME ZONE 'utc',
        $2,
        NOW() AT TIME ZONE 'utc' + INTERVAL '60 days',
        NULL
       ) RETURNING token, created_at, updated_at, user_id, expires_at, revoked_at
`

type CreateRefreshTokenParams struct {
	Token  string
	UserID uuid.UUID
}

func (q *Queries) CreateRefreshToken(ctx context.Context, arg CreateRefreshTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, createRefreshToken, arg.Token, arg.UserID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getUserFromRefreshToken = `-- name: GetUserFromRefreshToken :one
SELECT refresh_tokens.token, refresh_tokens.created_at, refresh_tokens.updated_at, refresh_tokens.user_id, refresh_tokens.expires_at, refresh_tokens.revoked_at, users.id, users.created_at, users.updated_at, users.email, users.hashed_password, users.is_chirpy_red FROM refresh_tokens
INNER JOIN users ON users.id = refresh_tokens.user_id
WHERE token = $1
`

type GetUserFromRefreshTokenRow struct {
	Token          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	UserID         uuid.UUID
	ExpiresAt      time.Time
	RevokedAt      sql.NullTime
	ID             uuid.UUID
	CreatedAt_2    time.Time
	UpdatedAt_2    time.Time
	Email          sql.NullString
	HashedPassword string
	IsChirpyRed    sql.NullBool
}

func (q *Queries) GetUserFromRefreshToken(ctx context.Context, token string) (GetUserFromRefreshTokenRow, error) {
	row := q.db.QueryRowContext(ctx, getUserFromRefreshToken, token)
	var i GetUserFromRefreshTokenRow
	err := row.Scan(
		&i.Token,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.UserID,
		&i.ExpiresAt,
		&i.RevokedAt,
		&i.ID,
		&i.CreatedAt_2,
		&i.UpdatedAt_2,
		&i.Email,
		&i.HashedPassword,
		&i.IsChirpyRed,
	)
	return i, err
}

const revokeRefreshToken = `-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = NOW() AT TIME ZONE 'utc', updated_at = NOW() AT TIME ZONE 'utc'
WHERE token = $1
`

func (q *Queries) RevokeRefreshToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeRefreshToken, token)
	return err
}
