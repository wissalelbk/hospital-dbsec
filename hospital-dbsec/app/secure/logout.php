<?php
require_once __DIR__ . '/audit.php';
if (session_status() === PHP_SESSION_NONE) { session_start(); }
if (!empty($_SESSION['uid'])) {
    log_event((int)$_SESSION['uid'], $_SESSION['username'] ?? null, 'LOGOUT');
}
$_SESSION = [];
session_destroy();
header('Location: login.php');
exit;
