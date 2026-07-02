CREATE TABLE IF NOT EXISTS dashboard_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS dashboard_users_email_idx
    ON dashboard_users (email);

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
    timezone TEXT NOT NULL DEFAULT 'UTC',
    internal_notes TEXT NOT NULL DEFAULT '',
    ssh_enabled BOOLEAN NOT NULL DEFAULT false,
    ssh_port INTEGER CHECK (ssh_port IS NULL OR (ssh_port >= 1 AND ssh_port <= 65535)),
    http_enabled BOOLEAN NOT NULL DEFAULT false,
    http_port INTEGER CHECK (http_port IS NULL OR (http_port >= 1 AND http_port <= 65535)),
    ftp_enabled BOOLEAN NOT NULL DEFAULT false,
    ftp_port INTEGER CHECK (ftp_port IS NULL OR (ftp_port >= 1 AND ftp_port <= 65535)),
    telnet_enabled BOOLEAN NOT NULL DEFAULT false,
    telnet_port INTEGER CHECK (telnet_port IS NULL OR (telnet_port >= 1 AND telnet_port <= 65535)),
    fake_users TEXT[] NOT NULL DEFAULT '{}',
    running_processes TEXT[] NOT NULL DEFAULT '{}',
    decoy_files JSONB NOT NULL DEFAULT '[]',
    alert_routing_level TEXT NOT NULL DEFAULT 'none' CHECK (alert_routing_level IN ('none', 'email', 'slack', 'both')),
    alert_min_risk_level TEXT CHECK (alert_min_risk_level IN ('critical', 'high', 'medium', 'low')),
    contact_email TEXT,
    slack_webhook TEXT,
    interaction_depth TEXT NOT NULL DEFAULT 'minimal' CHECK (interaction_depth IN ('minimal', 'standard', 'deep')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE persona_configs ADD COLUMN IF NOT EXISTS
    alert_min_risk_level TEXT CHECK (alert_min_risk_level IN ('critical', 'high', 'medium', 'low'));

INSERT INTO issues (
    id, title, severity, evidence, recommended_fix, impact,
    session_count, persona_count, status, created_at
) VALUES
    (
        '11111111-1111-4111-8111-111111111111',
        'SSH password authentication is being targeted.',
        'high',
        '37 brute-force sessions across 4 personas.',
        'Disable password login, enforce SSH keys, add rate limiting, block repeated scanner ASNs.',
        'Reduces credential-access exposure.',
        37, 4, 'open', now()
    ),
    (
        '22222222-2222-4222-8222-222222222222',
        'Attackers fingerprint the system before staging payloads.',
        'medium',
        '24 sessions ran whoami, uname -a, and cat /etc/passwd within the first 10 seconds across 3 personas.',
        'Trim shell banner detail, randomize first-command response timing, and alert on rapid fingerprinting sequences.',
        'Shortens attacker dwell time before detection.',
        24, 3, 'open', now()
    ),
    (
        '33333333-3333-4333-8333-333333333333',
        'Attackers plant SSH keys for persistence after login.',
        'high',
        '18 sessions appended to ~/.ssh/authorized_keys across 2 personas.',
        'Make ~/.ssh writes visibly detectable, seed decoy keys, and alert immediately on authorized_keys modification.',
        'Closes the most common persistence path observed.',
        18, 2, 'open', now()
    ),
    (
        '44444444-4444-4444-8444-444444444444',
        'The same scanner ASNs revisit after short cooldowns to re-validate access.',
        'medium',
        '12 sessions from 3 ASNs returned within 24 hours of a prior scan.',
        'Throttle by ASN with an escalating cooldown and block ranges that repeatedly re-validate without new behavior.',
        'Frees analyst attention for genuine attacker sessions.',
        12, 3, 'closed', now()
    )
ON CONFLICT (id) DO NOTHING;

INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES
    ('11111111-1111-4111-8111-111111111111', 0, 'T1110', 'Brute Force'),
    ('11111111-1111-4111-8111-111111111111', 1, 'T1078', 'Valid Accounts'),
    ('22222222-2222-4222-8222-222222222222', 0, 'T1082', 'System Information Discovery'),
    ('22222222-2222-4222-8222-222222222222', 1, 'T1087', 'Account Discovery'),
    ('33333333-3333-4333-8333-333333333333', 0, 'T1098.004', 'SSH Authorized Keys'),
    ('44444444-4444-4444-8444-444444444444', 0, 'T1595', 'Active Scanning')
ON CONFLICT (issue_id, technique_index) DO NOTHING;

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

-- One row per email alert that was attempted.
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
