DROP TABLE IF EXISTS manual_labels;
DROP TABLE IF EXISTS classifier_signals;
DROP TABLE IF EXISTS classifier_runs;
DROP TABLE IF EXISTS session_events;
DROP TABLE IF EXISTS sessions;

CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    protocol TEXT NOT NULL,
    peer_ip TEXT,
    peer_port INTEGER CHECK (peer_port IS NULL OR (peer_port >= 1 AND peer_port <= 65535)),
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
    notes TEXT
);

CREATE INDEX manual_labels_session_id_idx
    ON manual_labels (session_id);

CREATE INDEX manual_labels_classifier_run_id_idx
    ON manual_labels (classifier_run_id);
