<?php
/* Dashboard. BASELINE weakness: no real authorization — any logged-in
   user (even a patient) can reach every page/link. Authorization is only
   "hidden" in the UI, not enforced. (Fixed in ../secure with RBAC checks.) */
require_once __DIR__ . '/header.php';
if (empty($_SESSION['user'])) { header('Location: login.php'); exit; }
?>
<div class="card">
  <h2>Welcome, <?php echo htmlspecialchars($_SESSION['user']); ?></h2>
  <p>Role: <strong><?php echo htmlspecialchars($_SESSION['role']); ?></strong></p>
  <p>Use the navigation bar to search patients and open medical records.</p>
  <p style="font-size:12px;color:#b00020">
    Note (baseline): there is no server-side role enforcement here — every link
    works for every role. This is one of the weaknesses the hardened version fixes.
  </p>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
