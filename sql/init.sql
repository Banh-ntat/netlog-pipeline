CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Bảng sự kiện chính
CREATE TABLE IF NOT EXISTS events (
    id            BIGSERIAL,
    event_time    TIMESTAMPTZ NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL,
    device_name   TEXT,
    device_type   TEXT,
    source_ip     INET,
    facility      SMALLINT,
    severity      SMALLINT,
    severity_name TEXT,
    category      TEXT,
    event_code    TEXT,
    message       TEXT,
    src_ip        INET,
    dst_ip        INET,
    dst_port      INTEGER,
    action        TEXT,
    interface     TEXT,
    raw           TEXT,
    fingerprint   TEXT,
    PRIMARY KEY (id, event_time)
);

SELECT create_hypertable('events', 'event_time',
                         chunk_time_interval => INTERVAL '1 day',
                         if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_events_device_time ON events (device_name, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_sev_time    ON events (severity, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_code_time   ON events (event_code, event_time DESC);
CREATE INDEX IF NOT EXISTS idx_events_src_time    ON events (src_ip, event_time DESC);

-- Bảng cảnh báo
CREATE TABLE IF NOT EXISTS alerts (
    id           BIGSERIAL PRIMARY KEY,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    rule_name    TEXT NOT NULL,
    severity     TEXT NOT NULL,            -- low | medium | high | critical
    device_name  TEXT,
    entity       TEXT,                     -- IP hoặc interface liên quan
    description  TEXT,
    event_count  INTEGER,
    window_start TIMESTAMPTZ,
    window_end   TIMESTAMPTZ,
    status       TEXT NOT NULL DEFAULT 'open',   -- open | acknowledged | resolved
    dedup_key    TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_status  ON alerts (status);

-- Log không parse được
CREATE TABLE IF NOT EXISTS unparsed_logs (
    id          BIGSERIAL PRIMARY KEY,
    received_at TIMESTAMPTZ NOT NULL,
    source_ip   INET,
    raw         TEXT
);

-- Tự xóa dữ liệu cũ hơn 30 ngày
SELECT add_retention_policy('events', INTERVAL '30 days', if_not_exists => TRUE);
