<?php
require_once __DIR__ . '/header.php';
$cu = require_login();
?>
<div class="card">
  <h2>Welcome, <?php echo htmlspecialchars($cu['username']); ?></h2>
  <p>Role: <strong><?php echo htmlspecialchars($cu['role']); ?></strong></p>
  <p>Access is enforced server-side: you only see the actions permitted for your role.</p>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
