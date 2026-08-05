CREATE TABLE IF NOT EXISTS dashboard_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS dashboard_users_email_idx
    ON dashboard_users (email);

-- Bumped to invalidate every session cookie issued for this user (logout,
-- future password changes, account deletion) without a server-side session
-- store -- cookies carry the version they were issued with, and verification
-- rejects any cookie whose version no longer matches this column.
ALTER TABLE dashboard_users ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1;

-- Failed dashboard /auth/login attempts, keyed by client-ip:email. Backs the
-- login rate limiter in classifier/api/app.py with a store shared across all
-- API worker processes -- a process-local dict would let an attacker bypass
-- the limit by spreading requests across workers.
CREATE TABLE IF NOT EXISTS login_failures (
    id BIGSERIAL PRIMARY KEY,
    rate_limit_key TEXT NOT NULL,
    failed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS login_failures_key_idx
    ON login_failures (rate_limit_key, failed_at);

CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY,
    protocol TEXT NOT NULL,
    peer_ip TEXT,
    peer_port INTEGER CHECK (peer_port IS NULL OR (peer_port >= 1 AND peer_port <= 65535)),
    latitude DOUBLE PRECISION CHECK (latitude IS NULL OR (latitude >= -90 AND latitude <= 90)),
    longitude DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude >= -180 AND longitude <= 180)),
    country TEXT,
    persona_id TEXT NOT NULL,
    started_at DOUBLE PRECISION NOT NULL,
    ended_at DOUBLE PRECISION NOT NULL CHECK (ended_at >= started_at),
    end_reason TEXT NOT NULL
);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS latitude DOUBLE PRECISION
    CHECK (latitude IS NULL OR (latitude >= -90 AND latitude <= 90));
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS longitude DOUBLE PRECISION
    CHECK (longitude IS NULL OR (longitude >= -180 AND longitude <= 180));
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS country TEXT;

CREATE INDEX IF NOT EXISTS sessions_persona_id_idx
    ON sessions (persona_id);

CREATE INDEX IF NOT EXISTS sessions_started_at_idx
    ON sessions (started_at);

CREATE INDEX IF NOT EXISTS sessions_peer_ip_idx
    ON sessions (peer_ip);

CREATE TABLE IF NOT EXISTS session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    event_index INTEGER NOT NULL CHECK (event_index >= 0),
    event_type TEXT NOT NULL,
    event_value TEXT NOT NULL,
    observed_at DOUBLE PRECISION,
    UNIQUE (session_id, event_index)
);

CREATE INDEX IF NOT EXISTS session_events_session_id_idx
    ON session_events (session_id);

CREATE INDEX IF NOT EXISTS session_events_type_value_idx
    ON session_events (event_type, event_value);

CREATE TABLE IF NOT EXISTS classifier_runs (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_label TEXT,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL,
    behavior_stage TEXT NOT NULL,
    intent TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS classifier_runs_session_id_idx
    ON classifier_runs (session_id);

CREATE INDEX IF NOT EXISTS classifier_runs_risk_level_idx
    ON classifier_runs (risk_level);

CREATE INDEX IF NOT EXISTS classifier_runs_actor_label_idx
    ON classifier_runs (actor_label);

-- Whether this run classified a fully closed session or a still-in-progress
-- one (real-time partial classification) -- without this, a stored run with
-- an elevated risk_level can't be told apart from one whose classification
-- may still change once the session actually ends.
ALTER TABLE classifier_runs ADD COLUMN IF NOT EXISTS classification_status TEXT NOT NULL DEFAULT 'complete'
;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'classifier_runs_classification_status_check'
    ) THEN
        ALTER TABLE classifier_runs
            ADD CONSTRAINT classifier_runs_classification_status_check
            CHECK (classification_status IN ('complete', 'partial', 'insufficient_data'));
    END IF;
END $$;
ALTER TABLE classifier_runs ADD COLUMN IF NOT EXISTS insufficient_data_reason TEXT;

CREATE TABLE IF NOT EXISTS classifier_signals (
    id BIGSERIAL PRIMARY KEY,
    classifier_run_id UUID NOT NULL REFERENCES classifier_runs(id) ON DELETE CASCADE,
    signal_index INTEGER NOT NULL CHECK (signal_index >= 0),
    signal_type TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    signal_value TEXT NOT NULL,
    UNIQUE (classifier_run_id, signal_index)
);

CREATE INDEX IF NOT EXISTS classifier_signals_run_id_idx
    ON classifier_signals (classifier_run_id);

CREATE INDEX IF NOT EXISTS classifier_signals_type_key_idx
    ON classifier_signals (signal_type, signal_key);

CREATE TABLE IF NOT EXISTS manual_labels (
    id UUID PRIMARY KEY,
    classifier_run_id UUID REFERENCES classifier_runs(id) ON DELETE SET NULL,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_label TEXT,
    risk_level TEXT,
    behavior_stage TEXT,
    intent TEXT,
    notes TEXT,
    labeled_by TEXT,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS manual_labels_session_id_idx
    ON manual_labels (session_id);

CREATE INDEX IF NOT EXISTS manual_labels_classifier_run_id_idx
    ON manual_labels (classifier_run_id);

CREATE TABLE IF NOT EXISTS issues (
    id UUID PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
    evidence TEXT NOT NULL,
    recommended_fix TEXT NOT NULL,
    impact TEXT NOT NULL,
    session_count INTEGER NOT NULL CHECK (session_count >= 0),
    persona_count INTEGER NOT NULL CHECK (persona_count >= 0),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
    created_at TIMESTAMPTZ NOT NULL
);

-- Lets the dashboard link an issue straight to the Sessions page filtered to
-- the actor that drove it, instead of leaving analysts to search manually.
ALTER TABLE issues ADD COLUMN IF NOT EXISTS actor_label TEXT;

CREATE INDEX IF NOT EXISTS issues_status_idx
    ON issues (status);

CREATE TABLE IF NOT EXISTS issue_mitre_techniques (
    id BIGSERIAL PRIMARY KEY,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    technique_index INTEGER NOT NULL CHECK (technique_index >= 0),
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    UNIQUE (issue_id, technique_index)
);

CREATE INDEX IF NOT EXISTS issue_mitre_techniques_issue_id_idx
    ON issue_mitre_techniques (issue_id);

CREATE TABLE IF NOT EXISTS persona_configs (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    os_banner TEXT NOT NULL DEFAULT '',
    ssh_banner TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    internal_notes TEXT NOT NULL DEFAULT '',
    fake_users TEXT[] NOT NULL DEFAULT '{}',
    running_processes TEXT[] NOT NULL DEFAULT '{}',
    -- The fake web server the HTTP listener presents for this persona --
    -- an explicit choice, not inferred from running_processes (which stays
    -- free text purely for the fake `ps` output over the SSH shell). 'none'
    -- means the HTTP listener rejects every request for this persona
    -- (closes the connection with no response) rather than risk serving a
    -- page that contradicts what running_processes/hostname claim.
    http_server_type TEXT NOT NULL DEFAULT 'nginx' CHECK (http_server_type IN ('nginx', 'apache', 'busybox', 'none')),
    decoy_files JSONB NOT NULL DEFAULT '[]',
    alert_routing_level TEXT NOT NULL DEFAULT 'none' CHECK (alert_routing_level IN ('none', 'email', 'slack', 'both')),
    alert_min_risk_level TEXT CHECK (alert_min_risk_level IN ('critical', 'high', 'medium', 'low')),
    contact_email TEXT,
    slack_webhook TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE persona_configs ADD COLUMN IF NOT EXISTS
    alert_min_risk_level TEXT CHECK (alert_min_risk_level IN ('critical', 'high', 'medium', 'low'));

-- Adds http_server_type and, in the same one-time pass, backfills existing
-- rows from what _server_kind() used to infer from running_processes text
-- before this column existed -- an already-saved "apache" persona shouldn't
-- silently start serving nginx pages just because the column now defaults
-- to 'nginx'. Gated on the column not existing yet (rather than a WHERE
-- http_server_type = 'nginx' guard on a plain re-runnable UPDATE) because
-- 'nginx' is also a legitimate explicit choice, indistinguishable from the
-- untouched default once set -- a value-based guard would keep re-clobbering
-- an operator's later, deliberate 'nginx' selection on every re-run of
-- init-db (which is otherwise safe to re-run against a live database) if
-- running_processes still happens to mention "apache" as flavor text.
-- Gating on column existence instead makes the backfill run exactly once,
-- the moment the column is actually created, never again after.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'persona_configs' AND column_name = 'http_server_type'
    ) THEN
        ALTER TABLE persona_configs ADD COLUMN http_server_type TEXT NOT NULL
            DEFAULT 'nginx' CHECK (http_server_type IN ('nginx', 'apache', 'busybox', 'none'));

        UPDATE persona_configs
        SET http_server_type = CASE
            WHEN EXISTS (SELECT 1 FROM unnest(running_processes) p WHERE p ILIKE '%apache%') THEN 'apache'
            WHEN EXISTS (SELECT 1 FROM unnest(running_processes) p WHERE p ILIKE '%busybox%') THEN 'busybox'
            ELSE http_server_type
        END;
    END IF;
END $$;

-- timezone/interaction_depth were accepted and stored but never consumed
-- anywhere (interaction_depth's "Deep" option implied engagement-depth
-- control that was never implemented); the ssh/http/ftp/telnet *_enabled
-- and *_port pairs implied per-persona listener control that never existed
-- either -- the four listener ports are controlled once, globally, by
-- ECHIDRA_*_PORT env vars regardless of which persona is active. One
-- statement, not ten, for the same reason the columns above were added one
-- ALTER at a time: each represents a distinct historical change, but a
-- single removal pass reads as one deliberate cleanup, not a pile of drops.
ALTER TABLE persona_configs
    DROP COLUMN IF EXISTS timezone,
    DROP COLUMN IF EXISTS interaction_depth,
    DROP COLUMN IF EXISTS ssh_enabled,
    DROP COLUMN IF EXISTS ssh_port,
    DROP COLUMN IF EXISTS http_enabled,
    DROP COLUMN IF EXISTS http_port,
    DROP COLUMN IF EXISTS ftp_enabled,
    DROP COLUMN IF EXISTS ftp_port,
    DROP COLUMN IF EXISTS telnet_enabled,
    DROP COLUMN IF EXISTS telnet_port;

-- Singleton row holding global SMTP alert settings.
CREATE TABLE IF NOT EXISTS alert_config (
    id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT false,
    smtp_host TEXT,
    smtp_port INTEGER NOT NULL DEFAULT 587,
    smtp_username TEXT,
    smtp_password TEXT,
    smtp_from_email TEXT,
    smtp_use_tls BOOLEAN NOT NULL DEFAULT true,
    global_min_risk_level TEXT NOT NULL DEFAULT 'high'
        CHECK (global_min_risk_level IN ('critical', 'high', 'medium', 'low')),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-installation random salt for deriving the SMTP password encryption
-- key (see _alert_password_key in repository.py) -- generated once on first
-- use rather than a fixed value shared across every deployment.
ALTER TABLE alert_config ADD COLUMN IF NOT EXISTS smtp_password_salt TEXT;

-- Newline-separated list of source IPs that never trigger an alert, no
-- matter what a scoring rule concludes about them. Exists because rules
-- like repeat_connections_same_ip key off connection frequency from an IP,
-- not that connection's own content -- so an operator's own dev/test
-- traffic against a stable IP (eg. 127.0.0.1) will eventually self-trigger
-- a brute_force_bot/T1110 alert with no actual credential activity behind
-- it. This lets an operator silence known-noisy sources without touching
-- the scoring rules themselves.
ALTER TABLE alert_config ADD COLUMN IF NOT EXISTS excluded_ips TEXT;

-- One row per alert dispatch attempt (email or Slack).
CREATE TABLE IF NOT EXISTS alert_events (
    id UUID PRIMARY KEY,
    run_id UUID REFERENCES classifier_runs(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    persona_id TEXT NOT NULL,
    risk_level TEXT NOT NULL,
    actor_label TEXT,
    contact_email TEXT,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS alert_events_sent_at_idx
    ON alert_events (sent_at DESC);

CREATE INDEX IF NOT EXISTS alert_events_persona_id_idx
    ON alert_events (persona_id);

-- Which channel this dispatch attempt used. Doesn't carry the Slack webhook
-- URL itself (that stays only in persona_configs) -- same reasoning as
-- keeping the SMTP password out of alert_config's plaintext columns.
ALTER TABLE alert_events ADD COLUMN IF NOT EXISTS channel TEXT NOT NULL DEFAULT 'email';
