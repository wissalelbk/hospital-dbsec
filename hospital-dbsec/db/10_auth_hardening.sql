-- =====================================================================
--  Phase 11 (v2) — Authentication hardening
--  Adds: server-side PEPPER versioning, TOTP MFA, and an IP+account
--  rate-limit table that mitigates account-lockout denial of service.
--  Engine: MySQL 8.4 LTS  (run after db/05/06 are in place)
-- =====================================================================
USE hospital;

-- MFA + hash versioning on application accounts
ALTER TABLE app_users
    ADD COLUMN hash_version TINYINT       NOT NULL DEFAULT 1 AFTER password_hash,  -- 1=Argon2id, 2=pepper+Argon2id
    ADD COLUMN mfa_enabled  TINYINT(1)    NOT NULL DEFAULT 0,
    ADD COLUMN totp_secret  VARBINARY(255) NULL;   -- AES-GCM encrypted TOTP secret

-- Per-IP / per-account login throttle (anti brute force AND anti lockout-DoS)
CREATE TABLE IF NOT EXISTS login_throttle (
    id            BIGINT AUTO_INCREMENT PRIMARY KEY,
    scope         ENUM('ip','account') NOT NULL,
    scope_key     VARCHAR(128) NOT NULL,          -- the IP, or the username
    window_start  DATETIME     NOT NULL,
    attempts      INT          NOT NULL DEFAULT 0,
    blocked_until DATETIME     NULL,
    UNIQUE KEY uq_scope (scope, scope_key)
) ENGINE=InnoDB;

-- The least-privileged app account needs to manage throttle + read mfa columns
-- (append-only is not appropriate here; it must UPDATE counters)
-- GRANT SELECT,INSERT,UPDATE ON hospital.login_throttle TO 'app_svc'@'192.168.56.20';
