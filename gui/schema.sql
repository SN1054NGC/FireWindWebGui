PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS members(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  telegram TEXT,
  code TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS devices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER NOT NULL REFERENCES members(id) ON DELETE CASCADE,
  label TEXT,
  protocol TEXT NOT NULL,
  platform TEXT,
  vpn_name TEXT UNIQUE,
  token TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  link TEXT,
  config TEXT,
  traffic_limit_gb INTEGER,
  expires_at TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  decided_at TEXT,
  decided_by TEXT,
  note TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_member ON devices(member_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
CREATE TABLE IF NOT EXISTS invites(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT UNIQUE NOT NULL,
  max_uses INTEGER NOT NULL DEFAULT 1,
  uses INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT,
  note TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor TEXT, action TEXT, target TEXT, meta TEXT,
  ts TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS contributions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  member_id INTEGER,
  amount REAL,
  currency TEXT DEFAULT 'RUB',
  method TEXT,
  status TEXT DEFAULT 'pledged',
  public INTEGER DEFAULT 0,
  message TEXT,
  ts TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE TABLE IF NOT EXISTS client_apps(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  os TEXT,
  app TEXT NOT NULL,
  url TEXT NOT NULL,
  note TEXT,
  sort INTEGER DEFAULT 0
);