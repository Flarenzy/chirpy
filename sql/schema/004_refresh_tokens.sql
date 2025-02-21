-- +goose Up
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token TEXT PRIMARY KEY NOT NULL,
    created_at timestamp not null,
    updated_at timestamp not null,
    user_id uuid not null,
    expires_at timestamp not null,
    revoked_at timestamp,
    constraint fk_user_id foreign key (user_id) references users(id) on delete cascade
);

-- +goose Down
DROP TABLE refresh_tokens;