<?php
if (session_status() === PHP_SESSION_NONE) { session_start(); }
require_once __DIR__ . '/rbac.php';
require_once __DIR__ . '/audit.php';
$cu = current_user();
if ($cu) { set_db_actor($cu['username']); }   // so DB triggers log the human user
// Security response headers
header("Content-Security-Policy: default-src 'self'");
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rabat General Hospital — Patient Records (SECURE)</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1b2733}
 header{background:#0b6b3a;color:#fff;padding:10px 18px;display:flex;justify-content:space-between;align-items:center}
 header .tag{background:#063d21;padding:2px 8px;border-radius:4px;font-size:12px}
 nav{background:#0a5730;padding:6px 18px}
 nav a{color:#fff;margin-right:16px;text-decoration:none;font-size:14px}
 main{padding:20px;max-width:1000px;margin:0 auto}
 table{border-collapse:collapse;width:100%;background:#fff}
 th,td{border:1px solid #d7dde3;padding:6px 9px;font-size:13px;text-align:left}
 th{background:#eef1f4}
 input,button{padding:7px;font-size:14px}
 .card{background:#fff;border:1px solid #d7dde3;border-radius:6px;padding:16px;margin-bottom:16px}
 .err{color:#b00020;font-weight:bold}
</style>
</head>
<body>
<header>
  <strong>Rabat General Hospital — Patient Records</strong>
  <span class="tag">SECURE</span>
</header>
<?php if ($cu): ?>
<nav>
  <a href="dashboard.php">Dashboard</a>
  <?php if (in_array($cu['role'], ['DBA','Doctor','Nurse','Receptionist'], true)): ?>
    <a href="search.php">Patient search</a>
  <?php endif; ?>
  <?php if (in_array($cu['role'], ['DBA','Doctor','Nurse','Patient'], true)): ?>
    <a href="record.php">Medical records</a>
  <?php endif; ?>
  <a href="logout.php">Logout (<?php echo htmlspecialchars($cu['username']); ?> · <?php echo htmlspecialchars($cu['role']); ?>)</a>
</nav>
<?php endif; ?>
<main>
