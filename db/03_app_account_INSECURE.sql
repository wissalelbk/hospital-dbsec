-- =====================================================================
--  BASELINE — INSECURE application database access  (Vulnerability C)
--  This is the "attaque vierge" configuration: the web application
--  connects to MySQL as a super-privileged account.
--
--  WHY THIS IS THE VULNERABILITY:
--    * The app uses root@% (or an account with ALL PRIVILEGES).
--    * Any SQL-injection foothold in the app therefore inherits full
--      control of the DBMS: read every table, modify, DROP, read files,
--      create new DB users → total compromise.
--    * It violates the Principle of Least Privilege completely.
--
--  Remediated in db/04_roles_rbac_SECURE.sql (dedicated least-priv accounts).
-- =====================================================================

-- Baseline: the app simply reuses root (password 'root'), exposed on the network.
ALTER USER 'root'@'localhost' IDENTIFIED BY 'root';

-- Allow root to connect from the app server over the network (insecure).
CREATE USER IF NOT EXISTS 'root'@'192.168.56.20' IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'192.168.56.20' WITH GRANT OPTION;

-- (Equivalently some teams ship an "app" account that is just as over-privileged;
--  shown here so the before/after contrast is explicit.)
CREATE USER IF NOT EXISTS 'app'@'%' IDENTIFIED BY 'app';
GRANT ALL PRIVILEGES ON *.* TO 'app'@'%' WITH GRANT OPTION;   -- ⚠ everything, from anywhere

FLUSH PRIVILEGES;

-- Evidence to capture for the report (Phase 2 "before"):
--   SHOW GRANTS FOR 'app'@'%';
--   SELECT user, host FROM mysql.user;
