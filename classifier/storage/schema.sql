DROP TABLE IF EXISTS manual_labels;
DROP TABLE IF EXISTS classifier_signals;
DROP TABLE IF EXISTS classifier_runs;
DROP TABLE IF EXISTS session_events;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS dashboard_users;
DROP TABLE IF EXISTS issue_mitre_techniques;
DROP TABLE IF EXISTS issues;

CREATE TABLE dashboard_users (
    id UUID PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX dashboard_users_email_idx
    ON dashboard_users (email);

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    protocol TEXT NOT NULL,
    peer_ip TEXT,
    peer_port INTEGER CHECK (peer_port IS NULL OR (peer_port >= 1 AND peer_port <= 65535)),
    latitude DOUBLE PRECISION CHECK (latitude IS NULL OR (latitude >= -90 AND latitude <= 90)),
    longitude DOUBLE PRECISION CHECK (longitude IS NULL OR (longitude >= -180 AND longitude <= 180)),
    persona_id TEXT NOT NULL,
    started_at DOUBLE PRECISION NOT NULL,
    ended_at DOUBLE PRECISION NOT NULL CHECK (ended_at >= started_at),
    end_reason TEXT NOT NULL
);

CREATE INDEX sessions_persona_id_idx
    ON sessions (persona_id);

CREATE INDEX sessions_started_at_idx
    ON sessions (started_at);

CREATE TABLE session_events (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    event_index INTEGER NOT NULL CHECK (event_index >= 0),
    event_type TEXT NOT NULL,
    event_value TEXT NOT NULL,
    observed_at DOUBLE PRECISION,
    UNIQUE (session_id, event_index)
);

CREATE INDEX session_events_session_id_idx
    ON session_events (session_id);

CREATE INDEX session_events_type_value_idx
    ON session_events (event_type, event_value);

CREATE TABLE classifier_runs (
    id UUID PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    actor_label TEXT,
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    risk_score INTEGER NOT NULL CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_level TEXT NOT NULL,
    behavior_stage TEXT NOT NULL,
    intent TEXT NOT NULL
);

CREATE INDEX classifier_runs_session_id_idx
    ON classifier_runs (session_id);

CREATE INDEX classifier_runs_risk_level_idx
    ON classifier_runs (risk_level);

CREATE INDEX classifier_runs_actor_label_idx
    ON classifier_runs (actor_label);

CREATE TABLE classifier_signals (
    id BIGSERIAL PRIMARY KEY,
    classifier_run_id UUID NOT NULL REFERENCES classifier_runs(id) ON DELETE CASCADE,
    signal_index INTEGER NOT NULL CHECK (signal_index >= 0),
    signal_type TEXT NOT NULL,
    signal_key TEXT NOT NULL,
    signal_value TEXT NOT NULL,
    UNIQUE (classifier_run_id, signal_index)
);

CREATE INDEX classifier_signals_run_id_idx
    ON classifier_signals (classifier_run_id);

CREATE INDEX classifier_signals_type_key_idx
    ON classifier_signals (signal_type, signal_key);

CREATE TABLE manual_labels (
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

CREATE INDEX manual_labels_session_id_idx
    ON manual_labels (session_id);

CREATE INDEX manual_labels_classifier_run_id_idx
    ON manual_labels (classifier_run_id);

CREATE TABLE issues (
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

CREATE INDEX issues_status_idx
    ON issues (status);

CREATE TABLE issue_mitre_techniques (
    id BIGSERIAL PRIMARY KEY,
    issue_id UUID NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    technique_index INTEGER NOT NULL CHECK (technique_index >= 0),
    technique_id TEXT NOT NULL,
    technique_name TEXT NOT NULL,
    UNIQUE (issue_id, technique_index)
);

CREATE INDEX issue_mitre_techniques_issue_id_idx
    ON issue_mitre_techniques (issue_id);

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
    );

INSERT INTO issue_mitre_techniques (issue_id, technique_index, technique_id, technique_name) VALUES
    ('11111111-1111-4111-8111-111111111111', 0, 'T1110', 'Brute Force'),
    ('11111111-1111-4111-8111-111111111111', 1, 'T1078', 'Valid Accounts'),
    ('22222222-2222-4222-8222-222222222222', 0, 'T1082', 'System Information Discovery'),
    ('22222222-2222-4222-8222-222222222222', 1, 'T1087', 'Account Discovery'),
    ('33333333-3333-4333-8333-333333333333', 0, 'T1098.004', 'SSH Authorized Keys'),
    ('44444444-4444-4444-8444-444444444444', 0, 'T1595', 'Active Scanning');
