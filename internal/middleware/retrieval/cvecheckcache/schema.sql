CREATE TABLE IF NOT EXISTS middleware_retrieval_cvecheck_cache (
    ecosystem    TEXT        NOT NULL,             -- OSV ecosystem ('npm' | 'pypi' | 'Go')
    name         TEXT        NOT NULL,             -- package name / module path
    version      TEXT        NOT NULL,
    critical     INTEGER     NOT NULL DEFAULT 0,   -- vuln count at/above the stored min_severity filter
    high         INTEGER     NOT NULL DEFAULT 0,
    medium       INTEGER     NOT NULL DEFAULT 0,
    low          INTEGER     NOT NULL DEFAULT 0,
    unknown      INTEGER     NOT NULL DEFAULT 0,
    retrieved_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (ecosystem, name, version)
);
CREATE INDEX IF NOT EXISTS middleware_retrieval_cvecheck_cache_retrieved_at
    ON middleware_retrieval_cvecheck_cache (retrieved_at);
