<?php
/* SECURE DB connection: PDO, TLS, prepared statements only, exceptions on error. */
/* Load the app configuration unless the connection constants are already
   defined (lets an isolated test harness point db() at a lab instance). */
if (!defined('DB_HOST')) {
    require_once __DIR__ . '/config.php';
}

function db(): PDO {
    static $pdo = null;
    if ($pdo !== null) { return $pdo; }

    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
                   DB_HOST, DB_PORT, DB_NAME);

    $options = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,   // real server-side prepares
    ];
    // Enforce TLS in transit when the CA is present
    if (is_readable(DB_SSL_CA)) {
        $options[PDO::MYSQL_ATTR_SSL_CA] = DB_SSL_CA;
        $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
    }

    $pdo = new PDO($dsn, DB_USER, DB_PASS, $options);
    return $pdo;
}
