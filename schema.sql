-- ============================================================
--  BillEase — Supabase Schema
--  Run this entire file in: Supabase Dashboard → SQL Editor
-- ============================================================

-- ── USERS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name          TEXT NOT NULL,
  email         TEXT UNIQUE NOT NULL,
  password      TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'client',   -- 'admin' | 'client'
  verified      BOOLEAN NOT NULL DEFAULT false,
  verify_token  TEXT,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- Business / settings stored per user
  biz_name      TEXT NOT NULL DEFAULT 'My Store',
  biz_address   TEXT NOT NULL DEFAULT '',
  biz_phone     TEXT NOT NULL DEFAULT '',
  currency      TEXT NOT NULL DEFAULT '₹',
  tax_rate      NUMERIC NOT NULL DEFAULT 5,
  tax_enabled   BOOLEAN NOT NULL DEFAULT true,
  tax_name      TEXT NOT NULL DEFAULT 'GST',
  thank_you     TEXT NOT NULL DEFAULT 'Thank you for visiting!',
  bill_prefix   TEXT NOT NULL DEFAULT 'INV'
);

-- ── ITEMS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS items (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name       TEXT NOT NULL,
  price      NUMERIC NOT NULL,
  cat        TEXT NOT NULL DEFAULT 'General',
  emoji      TEXT NOT NULL DEFAULT '🛒',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── BILLS ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS bills (
  id         SERIAL PRIMARY KEY,
  no         INTEGER NOT NULL,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer   TEXT NOT NULL DEFAULT 'Guest',
  phone      TEXT NOT NULL DEFAULT '',
  tbl        TEXT NOT NULL DEFAULT '',
  cart       JSONB NOT NULL DEFAULT '[]',
  sub        NUMERIC NOT NULL DEFAULT 0,
  disc       NUMERIC NOT NULL DEFAULT 0,
  tax        NUMERIC NOT NULL DEFAULT 0,
  grand      NUMERIC NOT NULL DEFAULT 0,
  pay_mode   TEXT NOT NULL DEFAULT 'Cash',
  disc_type  TEXT NOT NULL DEFAULT 'flat',
  disc_val   NUMERIC NOT NULL DEFAULT 0,
  time       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── HELD BILLS ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS held_bills (
  id         BIGSERIAL PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  customer   TEXT NOT NULL DEFAULT 'Guest',
  tbl        TEXT NOT NULL DEFAULT '',
  cart       JSONB NOT NULL DEFAULT '[]',
  time       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ── BILL NUMBER SEQUENCE PER USER ────────────────────────────
CREATE TABLE IF NOT EXISTS bill_sequences (
  user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  next_no    INTEGER NOT NULL DEFAULT 1
);

-- ── INDEXES ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_items_user    ON items(user_id);
CREATE INDEX IF NOT EXISTS idx_bills_user    ON bills(user_id);
CREATE INDEX IF NOT EXISTS idx_bills_time    ON bills(time);
CREATE INDEX IF NOT EXISTS idx_held_user     ON held_bills(user_id);
CREATE INDEX IF NOT EXISTS idx_users_email   ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_token   ON users(verify_token);

-- ── ROW LEVEL SECURITY (optional but recommended) ────────────
ALTER TABLE users       ENABLE ROW LEVEL SECURITY;
ALTER TABLE items       ENABLE ROW LEVEL SECURITY;
ALTER TABLE bills       ENABLE ROW LEVEL SECURITY;
ALTER TABLE held_bills  ENABLE ROW LEVEL SECURITY;

-- Allow service_role (your server) full access (bypasses RLS)
-- Your server uses the service_role key so RLS won't block it

-- ── SEED: DEFAULT ADMIN USER ─────────────────────────────────
-- Password: "password" (bcrypt hash)
INSERT INTO users (id, name, email, password, role, verified, biz_name)
VALUES (
  'admin-001',
  'Super Admin',
  'admin@billease.com',
  '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
  'admin',
  true,
  'BillEase Admin'
) ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Done! Now copy your Supabase URL and service_role key
-- from: Project Settings → API → Project URL & service_role
-- ============================================================
