CREATE TABLE IF NOT EXISTS denied_packages (
    registry     TEXT        NOT NULL,             -- 'npm' | 'pypi' | 'goproxy'
    name         TEXT        NOT NULL,             -- package name / module path
    version      TEXT        NOT NULL,
    artifact_id  TEXT        NOT NULL DEFAULT '',  -- pypi filename; '' for npm/goproxy
    sha256       TEXT        NOT NULL,             -- lowercase hex sha256 of the tarball
    project_key  TEXT        NOT NULL DEFAULT '',  -- '' = projectless (default) scope
    reason       TEXT        NOT NULL,             -- stored validation failure reason
    middleware   TEXT        NOT NULL DEFAULT '',  -- middleware that denied
    denied_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (registry, name, version, sha256, project_key)
);
CREATE INDEX IF NOT EXISTS denied_packages_project_key
    ON denied_packages (project_key);
CREATE INDEX IF NOT EXISTS denied_packages_name_version
    ON denied_packages (registry, name, version);
