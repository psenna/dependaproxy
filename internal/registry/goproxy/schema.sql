-- H2: project_key is part of the trust anchor's identity, not just an index.
-- Without it, one project's validation policy (which may run a weaker chain
-- than another project's) determines what every other project is served from
-- this table on a cache hit -- see internal/registry/goproxy/routes.go
-- serveTrusted. Existing deployments created before this column existed must
-- be migrated by hand (ADD COLUMN project_key TEXT NOT NULL DEFAULT '', then
-- rebuild the primary key to include it) before upgrading; CREATE TABLE IF
-- NOT EXISTS below only takes effect on a fresh install.
CREATE TABLE IF NOT EXISTS goproxy_validated_modules (
    project_key     TEXT        NOT NULL DEFAULT '', -- '' = projectless (default) scope
    module_path     TEXT        NOT NULL,
    version         TEXT        NOT NULL,
    validation_hash TEXT        NOT NULL,
    validated_at    TIMESTAMPTZ NOT NULL,
    metadata        JSONB,
    PRIMARY KEY (project_key, module_path, version)
);
