PRAGMA foreign_keys = ON;

CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at_us INTEGER NOT NULL CHECK (applied_at_us > 0)
) STRICT;

CREATE TABLE analyses (
    id TEXT PRIMARY KEY CHECK (id GLOB 'an_[0-9a-f]*' AND length(id) = 35),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    tool_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'canceled')),
    started_at_us INTEGER NOT NULL CHECK (started_at_us > 0),
    finished_at_us INTEGER,
    first_event_at_us INTEGER,
    last_event_at_us INTEGER,
    input_format TEXT NOT NULL CHECK (
        input_format IN ('nginx-combined', 'nginx-json', 'caddy-json', 'crawlledger-json')
    ),
    catalog_version TEXT NOT NULL,
    key_id TEXT NOT NULL CHECK (length(key_id) = 16),
    config_json TEXT NOT NULL CHECK (json_valid(config_json)),
    total_lines INTEGER NOT NULL DEFAULT 0 CHECK (total_lines >= 0),
    accepted_lines INTEGER NOT NULL DEFAULT 0 CHECK (accepted_lines >= 0),
    rejected_lines INTEGER NOT NULL DEFAULT 0 CHECK (rejected_lines >= 0),
    skipped_lines INTEGER NOT NULL DEFAULT 0 CHECK (skipped_lines >= 0),
    total_bytes INTEGER NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
    request_duration_us INTEGER CHECK (request_duration_us >= 0),
    upstream_duration_us INTEGER CHECK (upstream_duration_us >= 0),
    rate_model_requests INTEGER NOT NULL DEFAULT 0 CHECK (rate_model_requests >= 0),
    route_overflow_requests INTEGER NOT NULL DEFAULT 0 CHECK (route_overflow_requests >= 0),
    ua_overflow_requests INTEGER NOT NULL DEFAULT 0 CHECK (ua_overflow_requests >= 0),
    failure_code TEXT,
    failure_message TEXT,
    CHECK (
        (status = 'running' AND finished_at_us IS NULL) OR
        (status <> 'running' AND finished_at_us IS NOT NULL)
    ),
    CHECK (accepted_lines + rejected_lines + skipped_lines = total_lines)
) STRICT;

CREATE TABLE source_files (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    compression TEXT NOT NULL CHECK (compression IN ('plain', 'gzip')),
    compressed_bytes INTEGER CHECK (compressed_bytes >= 0),
    uncompressed_bytes INTEGER NOT NULL DEFAULT 0 CHECK (uncompressed_bytes >= 0),
    content_sha256 TEXT CHECK (content_sha256 IS NULL OR length(content_sha256) = 64),
    total_lines INTEGER NOT NULL DEFAULT 0 CHECK (total_lines >= 0),
    accepted_lines INTEGER NOT NULL DEFAULT 0 CHECK (accepted_lines >= 0),
    rejected_lines INTEGER NOT NULL DEFAULT 0 CHECK (rejected_lines >= 0),
    skipped_lines INTEGER NOT NULL DEFAULT 0 CHECK (skipped_lines >= 0),
    PRIMARY KEY (analysis_id, ordinal),
    CHECK (accepted_lines + rejected_lines + skipped_lines = total_lines)
) STRICT, WITHOUT ROWID;

CREATE TABLE user_agents (
    id INTEGER PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    ua_hash TEXT NOT NULL CHECK (length(ua_hash) = 64),
    claimed_crawler TEXT,
    claimed_category TEXT CHECK (
        claimed_category IS NULL OR claimed_category IN (
            'claimed_ai_crawler',
            'claimed_search_crawler',
            'claimed_other_crawler'
        )
    ),
    protected_default INTEGER NOT NULL DEFAULT 0 CHECK (protected_default IN (0, 1)),
    is_overflow INTEGER NOT NULL DEFAULT 0 CHECK (is_overflow IN (0, 1)),
    UNIQUE (analysis_id, ua_hash)
) STRICT;

CREATE TABLE routes (
    id INTEGER PRIMARY KEY,
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    normalized_path TEXT NOT NULL CHECK (
        length(CAST(normalized_path AS BLOB)) BETWEEN 1 AND 512
    ),
    actionable_prefix TEXT CHECK (
        actionable_prefix IS NULL OR
        (
            length(CAST(actionable_prefix AS BLOB)) BETWEEN 1 AND 256 AND
            substr(actionable_prefix, 1, 1) = '/'
        )
    ),
    is_overflow INTEGER NOT NULL DEFAULT 0 CHECK (is_overflow IN (0, 1))
) STRICT;

CREATE TABLE traffic_cells (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    bucket_minute_us INTEGER NOT NULL CHECK (bucket_minute_us >= 0),
    route_id INTEGER NOT NULL REFERENCES routes(id),
    user_agent_id INTEGER NOT NULL REFERENCES user_agents(id),
    primary_class TEXT NOT NULL CHECK (
        primary_class IN (
            'claimed_ai_crawler',
            'claimed_search_crawler',
            'claimed_other_crawler',
            'security_probe',
            'unclassified'
        )
    ),
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL CHECK (status_code BETWEEN 100 AND 599),
    cache_state TEXT NOT NULL CHECK (
        cache_state IN ('hit', 'miss', 'bypass', 'expired', 'stale', 'unknown')
    ),
    requests INTEGER NOT NULL CHECK (requests > 0),
    bytes_sent INTEGER NOT NULL CHECK (bytes_sent >= 0),
    request_duration_us INTEGER,
    request_duration_samples INTEGER NOT NULL CHECK (request_duration_samples >= 0),
    upstream_duration_us INTEGER,
    upstream_duration_samples INTEGER NOT NULL CHECK (upstream_duration_samples >= 0),
    referer_present INTEGER NOT NULL CHECK (referer_present >= 0),
    PRIMARY KEY (
        analysis_id,
        bucket_minute_us,
        route_id,
        user_agent_id,
        primary_class,
        method,
        status_code,
        cache_state
    ),
    CHECK (
        (request_duration_samples = 0 AND request_duration_us IS NULL) OR
        (request_duration_samples > 0 AND request_duration_us >= 0)
    ),
    CHECK (
        (upstream_duration_samples = 0 AND upstream_duration_us IS NULL) OR
        (upstream_duration_samples > 0 AND upstream_duration_us >= 0)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE route_stats (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    route_id INTEGER NOT NULL REFERENCES routes(id),
    requests INTEGER NOT NULL CHECK (requests >= 0),
    query_requests INTEGER NOT NULL CHECK (query_requests >= 0),
    status_404 INTEGER NOT NULL CHECK (status_404 >= 0),
    cache_misses INTEGER NOT NULL CHECK (cache_misses >= 0),
    bytes_sent INTEGER NOT NULL CHECK (bytes_sent >= 0),
    upstream_duration_us INTEGER,
    distinct_clients_kmv BLOB NOT NULL,
    distinct_urls_kmv BLOB NOT NULL,
    distinct_queries_kmv BLOB NOT NULL,
    PRIMARY KEY (analysis_id, route_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE subject_stats (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    client_key TEXT NOT NULL CHECK (length(client_key) = 32),
    user_agent_id INTEGER NOT NULL REFERENCES user_agents(id),
    requests INTEGER NOT NULL CHECK (requests >= 0),
    status_4xx INTEGER NOT NULL CHECK (status_4xx >= 0),
    no_referer INTEGER NOT NULL CHECK (no_referer >= 0),
    probe_requests INTEGER NOT NULL CHECK (probe_requests >= 0),
    robots_violations INTEGER NOT NULL CHECK (robots_violations >= 0),
    distinct_routes_kmv BLOB NOT NULL,
    first_seen_us INTEGER NOT NULL,
    last_seen_us INTEGER NOT NULL,
    PRIMARY KEY (analysis_id, client_key, user_agent_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE rate_profile_impacts (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    user_agent_id INTEGER NOT NULL REFERENCES user_agents(id),
    primary_class TEXT NOT NULL CHECK (
        primary_class IN (
            'claimed_ai_crawler',
            'claimed_search_crawler',
            'claimed_other_crawler',
            'security_probe',
            'unclassified'
        )
    ),
    profile TEXT NOT NULL CHECK (profile IN ('gentle', 'standard', 'strict')),
    modeled_requests INTEGER NOT NULL CHECK (modeled_requests >= 0),
    allowed_requests INTEGER NOT NULL CHECK (allowed_requests >= 0),
    limited_requests INTEGER NOT NULL CHECK (limited_requests >= 0),
    allowed_bytes INTEGER NOT NULL CHECK (allowed_bytes >= 0),
    limited_bytes INTEGER NOT NULL CHECK (limited_bytes >= 0),
    limited_upstream_us INTEGER,
    limited_upstream_samples INTEGER NOT NULL CHECK (limited_upstream_samples >= 0),
    PRIMARY KEY (analysis_id, user_agent_id, primary_class, profile),
    CHECK (modeled_requests = allowed_requests + limited_requests),
    CHECK (limited_upstream_samples <= limited_requests),
    CHECK (
        (limited_upstream_samples = 0 AND limited_upstream_us IS NULL) OR
        (limited_upstream_samples > 0 AND limited_upstream_us >= 0)
    )
) STRICT, WITHOUT ROWID;

CREATE TABLE robots_violations (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    user_agent_id INTEGER NOT NULL REFERENCES user_agents(id),
    route_id INTEGER NOT NULL REFERENCES routes(id),
    requests INTEGER NOT NULL CHECK (requests > 0),
    PRIMARY KEY (analysis_id, user_agent_id, route_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE route_query_keys (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    route_id INTEGER NOT NULL REFERENCES routes(id),
    query_key TEXT NOT NULL CHECK (length(query_key) BETWEEN 1 AND 80),
    requests INTEGER NOT NULL CHECK (requests > 0),
    PRIMARY KEY (analysis_id, route_id, query_key)
) STRICT, WITHOUT ROWID;

CREATE TABLE probe_hits (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    probe_id TEXT NOT NULL,
    route_id INTEGER NOT NULL REFERENCES routes(id),
    requests INTEGER NOT NULL CHECK (requests > 0),
    PRIMARY KEY (analysis_id, probe_id, route_id)
) STRICT, WITHOUT ROWID;

CREATE TABLE findings (
    id TEXT PRIMARY KEY CHECK (id GLOB 'fd_[0-9a-f]*' AND length(id) = 19),
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    route_id INTEGER REFERENCES routes(id),
    subject_key TEXT,
    confidence TEXT NOT NULL CHECK (confidence IN ('low', 'medium', 'high')),
    recommended_action TEXT NOT NULL,
    evidence_json TEXT NOT NULL CHECK (json_valid(evidence_json)),
    UNIQUE (analysis_id, kind, route_id, subject_key)
) STRICT;

CREATE TABLE parse_errors (
    analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
    source_ordinal INTEGER NOT NULL,
    line_number INTEGER NOT NULL CHECK (line_number > 0),
    code TEXT NOT NULL,
    PRIMARY KEY (analysis_id, source_ordinal, line_number),
    FOREIGN KEY (analysis_id, source_ordinal)
        REFERENCES source_files (analysis_id, ordinal)
        ON DELETE CASCADE
) STRICT, WITHOUT ROWID;

CREATE INDEX idx_traffic_cells_route
    ON traffic_cells (analysis_id, route_id);
CREATE UNIQUE INDEX idx_routes_identity
    ON routes (analysis_id, normalized_path, coalesce(actionable_prefix, ''));
CREATE INDEX idx_traffic_cells_ua
    ON traffic_cells (analysis_id, user_agent_id, primary_class);
CREATE INDEX idx_findings_kind_severity
    ON findings (analysis_id, severity, kind);

INSERT INTO schema_migrations (version, applied_at_us)
VALUES (1, CAST(unixepoch('subsec') * 1000000 AS INTEGER));

PRAGMA user_version = 1;
