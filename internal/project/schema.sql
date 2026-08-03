CREATE TABLE IF NOT EXISTS projects (
    key        TEXT        NOT NULL PRIMARY KEY,
    config     TEXT        NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS project_dependencies (
    project_key        TEXT        NOT NULL,
    registry           TEXT        NOT NULL,
    pkg                TEXT        NOT NULL,
    version            TEXT        NOT NULL,
    artifact_id        TEXT        NOT NULL DEFAULT '',
    sha256             TEXT        NOT NULL,
    first_downloaded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_downloaded_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    download_count     BIGINT      NOT NULL DEFAULT 1,
    CONSTRAINT project_dependencies_identity UNIQUE
        (project_key, registry, pkg, version, artifact_id, sha256)
);
CREATE INDEX IF NOT EXISTS project_dependencies_project_pkg
    ON project_dependencies (project_key, pkg);
