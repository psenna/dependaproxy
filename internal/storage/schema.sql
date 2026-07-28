CREATE TABLE IF NOT EXISTS validated_packages (
    name            TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    registry        TEXT        NOT NULL,
    validation_hash TEXT        NOT NULL,
    validated_at    TIMESTAMPTZ NOT NULL,
    metadata        JSONB,
    PRIMARY KEY (name, version, registry)
);