// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.28.0
// source: users.sql

package database

import (
	"context"
	"database/sql"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email)
VALUES (
        gen_random_uuid(),
        NOW() at time zone 'utc',
        NOW() at time zone 'utc',
        $1
       ) RETURNING id, created_at, updated_at, email
`

func (q *Queries) CreateUser(ctx context.Context, email sql.NullString) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
	)
	return i, err
}
