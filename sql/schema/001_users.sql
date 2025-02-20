-- +goose Up
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    created_at timestamp not null,
    updated_at timestamp not null,
    email TEXT UNIQUE
);

-- +goose Down
DROP TABLE users;