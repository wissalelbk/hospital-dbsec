<?php
/* BASELINE DB connection (insecure): plain mysqli, root account, no TLS. */
require_once __DIR__ . '/config.php';

$conn = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if (!$conn) {
    // ⚠ Verbose connection error (reveals host/engine details)
    die('DB connection failed: ' . mysqli_connect_error());
}
mysqli_set_charset($conn, 'utf8mb4');
