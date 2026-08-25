-- H2: project_key is part of the trust anchor's identity, not just an index.
-- Without it, one project's validation policy (which may run a weaker chain
-- than another project's) determines what every other project is served from
-- this table on a cache hit -- see internal/registry/pypi/routes.go
-- serveTrusted. Existing deployments created before this column existed must
-- be migrated by hand (ADD COLUMN project_key TEXT NOT NULL DEFAULT '', then
-- rebuild the primary key to include it) before upgrading; CREATE TABLE IF
-- NOT EXISTS below only takes effect on a fresh install.
CREATE TABLE IF NOT EXISTS pypi_validated_files (
    project_key     TEXT        NOT NULL DEFAULT '', -- '' = projectless (default) scope
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
    PRIMARY KEY (project_key, name, version, filename)
);
CREATE INDEX IF NOT EXISTS pypi_validated_files_name_version ON pypi_validated_files (name, version);
