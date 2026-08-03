CREATE TABLE IF NOT EXISTS projects (
    key        TEXT        NOT NULL PRIMARY KEY,
    config     TEXT        NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
