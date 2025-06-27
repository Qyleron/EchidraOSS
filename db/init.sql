-- Create DB (optional, usually handled separately)
-- CREATE DATABASE echidra_oss;

-- Connect to DB (only used in psql CLI, safe to omit in scripts)
-- \c echidra_oss;

-- Create table if not exists
CREATE TABLE IF NOT EXISTS sessions (
  id SERIAL PRIMARY KEY,
  ip_address TEXT,
  protocol TEXT,
  data JSONB,
  timestamp TIMESTAMPTZ DEFAULT now()
);


CREATE TABLE IF NOT EXISTS interactions (
  id SERIAL PRIMARY KEY,
  ip TEXT,
  port INT,
  service TEXT,
  data TEXT,
  timestamp TIMESTAMPTZ DEFAULT now()
);
