<?php
/* =====================================================================
 *  SECURE configuration  —  hardened Hospital Records app
 *   - connects as the LEAST-PRIVILEGE app_svc account (not root)
 *   - TLS required to the DB server (data in transit)
 *   - errors logged, NOT shown to the user
 *   - Argon2id parameters per OWASP 2026 (m=64MiB, t=3, p=1)
 * ===================================================================== */

define('DB_HOST', '192.168.56.10');
define('DB_NAME', 'hospital');
define('DB_USER', 'app_svc');                 // least privilege
define('DB_PASS', getenv('APP_DB_PASS') ?: 'App$vc#Change!2026');  // prefer env/secret
define('DB_PORT', 3306);

// TLS to MySQL (Phase 6 — data in transit). Point to the CA used on db-vm.
define('DB_SSL_CA', '/etc/mysql/ssl/ca.pem');

// Argon2id tuning (OWASP Password Storage Cheat Sheet, 2026)
define('ARGON_OPTS', [
    'memory_cost' => 65536,   // 64 MiB
    'time_cost'   => 3,
    'threads'     => 1,
]);

// Account lockout policy
define('MAX_FAILED_ATTEMPTS', 5);
define('LOCKOUT_MINUTES', 15);

// Do not leak internals to users
ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);
