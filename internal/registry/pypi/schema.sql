CREATE TABLE IF NOT EXISTS pypi_validated_files (
    name            TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    filename        TEXT        NOT NULL,
    filetype        TEXT        NOT NULL,         -- 'wheel' | 'sdist'
    python_tag      TEXT        NOT NULL DEFAULT '',
    abi_tag         TEXT        NOT NULL DEFAULT '',
    platform_tag    TEXT        NOT NULL DEFAULT '',
    sha256          TEXT        NOT NULL,
    requires_python TEXT        NOT NULL DEFAULT '',
    yanked          BOOLEAN     NOT NULL DEFAULT FALSE,
    validated_at    TIMESTAMPTZ NOT NULL,
    metadata        JSONB,
    PRIMARY KEY (name, version, filename)
);
CREATE INDEX IF NOT EXISTS pypi_validated_files_name_version ON pypi_validated_files (name, version);