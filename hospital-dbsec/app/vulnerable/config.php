<?php
/* =====================================================================
 *  BASELINE (INSECURE) configuration  —  "attaque vierge"
 *  Hospital Patient Records System  —  Database Security (UIR ING5)
 *
 *  Deliberate weaknesses in this file:
 *   - The web app connects to MySQL as ROOT (all privileges).  → Vuln C
 *   - Trivial password, no TLS to the DB server.               → Vuln D (transit)
 *   - PHP errors are shown to the user (helps an attacker).     → aids SQLi
 *
 *  The secure counterpart lives in ../secure/config.php
 * ===================================================================== */

define('DB_HOST', '192.168.56.10');   // db-vm
define('DB_USER', 'root');            // ⚠ super-privileged account
define('DB_PASS', 'root');            // ⚠ trivial password
define('DB_NAME', 'hospital');

// ⚠ Verbose errors leak SQL/structure to attackers
ini_set('display_errors', 1);
error_reporting(E_ALL);
