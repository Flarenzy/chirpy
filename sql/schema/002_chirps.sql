-- +goose Up
CREATE TABLE IF NOT EXISTS chirps (
    id UUID PRIMARY KEY,
    created_at timestamp not null,
    updated_at timestamp not null,
    body TEXT NOT NULL,
    user_id UUID NOT NULL,
    CONSTRAINT fk_userid FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- +goose Down
DROP TABLE chirps;