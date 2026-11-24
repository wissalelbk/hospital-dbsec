-- =====================================================================
--  Phase 9 — Database hardening  (MySQL 8.4 LTS, run on db-vm)
--  Reduces the attack surface and enforces secure defaults. Each block maps
--  to a hardening item in the brief and is justified in docs/phase9-hardening.md.
--  Run AFTER db/04 (RBAC) and db/07 (audit).
-- =====================================================================

-- 1) Remove default / anonymous / unnecessary accounts -----------------
DELETE FROM mysql.user WHERE User='';                 -- anonymous users
DROP DATABASE IF EXISTS test;                         -- sample DB (if present)
DELETE FROM mysql.db WHERE Db IN ('test','test\\_%'); -- stale test grants
-- root reachable only locally (network root was removed in db/04):
RENAME USER 'root'@'%' TO 'root'@'localhost';         -- no-op if already localhost-only
FLUSH PRIVILEGES;

-- 2) Enforce least privilege (verify, then tighten) --------------------
-- The over-privileged baseline accounts were dropped in db/04. Confirm no
-- application-facing account holds global or GRANT privileges:
--   SELECT user, host FROM mysql.user WHERE Super_priv='Y' OR Grant_priv='Y';
REVOKE GRANT OPTION ON *.* FROM 'app_svc'@'192.168.56.20';  -- belt & braces

-- 3) Strong password policy (MySQL 8 validate_password component) ------
INSTALL COMPONENT 'file://component_validate_password';
SET PERSIST validate_password.policy        = 'STRONG';
SET PERSIST validate_password.length        = 12;
SET PERSIST validate_password.mixed_case_count = 1;
SET PERSIST validate_password.number_count   = 1;
SET PERSIST validate_password.special_char_count = 1;

-- 4) Reduce engine attack surface / force TLS --------------------------
SET PERSIST require_secure_transport = ON;   -- refuse non-TLS connections (ties to CVE-2025-15467 surface)
SET PERSIST local_infile             = OFF;  -- block LOAD DATA LOCAL abuse
-- X Plugin (port 33060) — disable if the X Protocol is unused (CVE-2026-60316):
UNINSTALL PLUGIN mysqlx;                      -- or set mysqlx=OFF in my.cnf

-- 5) Logging / auditing on (Phase 7 objects + error log retained) ------
SET PERSIST log_error_verbosity = 2;
-- (audit_log table + triggers come from db/07_audit.sql)

FLUSH PRIVILEGES;

-- =====================================================================
--  Configuration-file hardening (/etc/mysql/mysql.conf.d/mysqld.cnf)
--  Apply then: systemctl restart mysql
-- ---------------------------------------------------------------------
--  [mysqld]
--  bind-address           = 192.168.56.10     # not 0.0.0.0 — only the lab NIC
--  mysqlx                 = OFF                # disable X Plugin (CVE-2026-60316)
--  local_infile           = OFF
--  skip_symbolic_links    = ON
--  secure_file_priv       = /var/lib/mysql-files
--  require_secure_transport= ON
--  log_error              = /var/log/mysql/error.log
--  log_bin                = /var/log/mysql/binlog   # for PITR (Phase 8)
--
--  Host firewall (db-vm): allow 3306 ONLY from app-vm
--    ufw default deny incoming
--    ufw allow from 192.168.56.20 to any port 3306 proto tcp
--    ufw enable
-- =====================================================================
