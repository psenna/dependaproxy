CREATE TABLE IF NOT EXISTS goproxy_validated_modules (
    module_path     TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    validation_hash TEXT        NOT NULL,
    validated_at    TIMESTAMPTZ NOT NULL,
    metadata        JSONB,
    PRIMARY KEY (module_path, version)
);
