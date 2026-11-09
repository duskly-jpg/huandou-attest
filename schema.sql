CREATE TABLE IF NOT EXISTS attest_challenge (
  id          TEXT PRIMARY KEY,
  challenge   BLOB NOT NULL,
  install_id  TEXT,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  consumed    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_attest_exp ON attest_challenge(expires_at);

-- 设备表：device_id 服务端生成，按 verifiedBootKey（同一设备的稳定指纹）复用。
-- revoked=1 后 /v1/config 拒绝、bind 也拒绝（防吊销后重新 bind 绕过）。
CREATE TABLE IF NOT EXISTS attest_devices (
  device_id    TEXT PRIMARY KEY,
  boot_key     BLOB NOT NULL UNIQUE,
  level        INTEGER NOT NULL,
  version_code INTEGER NOT NULL,
  created_at   INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  revoked      INTEGER NOT NULL DEFAULT 0
);

-- 配置下发：单行 JSON（id='config'），由 D1 更新维护；etag 随内容变
CREATE TABLE IF NOT EXISTS attest_config (
  id         TEXT PRIMARY KEY,
  value      TEXT NOT NULL,
  etag       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attest_session (
  id          TEXT PRIMARY KEY,
  chain_hash  BLOB NOT NULL,
  challenge   BLOB NOT NULL,
  step        INTEGER NOT NULL,
  total       INTEGER NOT NULL,
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_exp ON attest_session(expires_at);
