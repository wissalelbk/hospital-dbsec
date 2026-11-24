<?php
/* Minimal shared layout. UI is intentionally plain — the brief grades
   database security, not web design. */
if (session_status() === PHP_SESSION_NONE) { session_start(); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Rabat General Hospital — Records (BASELINE)</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1b2733}
 header{background:#b00020;color:#fff;padding:10px 18px;display:flex;justify-content:space-between;align-items:center}
 header .tag{background:#000;padding:2px 8px;border-radius:4px;font-size:12px}
 nav{background:#8a0019;padding:6px 18px}
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
  <span class="tag">BASELINE / INSECURE</span>
</header>
<?php if (!empty($_SESSION['user'])): ?>
<nav>
  <a href="dashboard.php">Dashboard</a>
  <a href="search.php">Patient search</a>
  <a href="record.php?patient_id=1">Medical records</a>
  <a href="logout.php">Logout (<?php echo htmlspecialchars($_SESSION['user']); ?> · <?php echo htmlspecialchars($_SESSION['role']); ?>)</a>
</nav>
<?php endif; ?>
<main>
