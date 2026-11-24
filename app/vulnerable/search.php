<?php
/* =====================================================================
 *  VULNERABLE patient search  (Vuln A: SQLi / UNION  +  Vuln D: clear PII)
 *
 *  Root causes:
 *   1. The query parameter $q is concatenated into a LIKE clause → the
 *      input can break out and inject UNION SELECT to dump any table.
 *   2. The result set prints national_id (sensitive) in cleartext.
 *   3. Runs with the root DB connection → UNION can reach every table,
 *      including app_users.password_hash.
 * ===================================================================== */
require_once __DIR__ . '/header.php';
if (empty($_SESSION['user'])) { header('Location: login.php'); exit; }
require_once __DIR__ . '/db.php';

$q = $_GET['q'] ?? '';
$rows = [];
$ran = false;
if ($q !== '') {
    $ran = true;
    // ⚠⚠ DANGEROUS: untrusted $q interpolated straight into the query
    $sql = "SELECT patient_id, national_id, first_name, last_name,
                   date_of_birth, phone, blood_type
            FROM patients
            WHERE last_name LIKE '%$q%' OR first_name LIKE '%$q%'";
    $res = mysqli_query($conn, $sql);
    if (!$res) {
        echo '<p class="err">Query error: ' . mysqli_error($conn) . '</p>'; // ⚠ verbose
    } else {
        while ($r = mysqli_fetch_assoc($res)) { $rows[] = $r; }
    }
}
?>
<div class="card">
  <h2>Patient search</h2>
  <form method="get" action="search.php">
    <input name="q" value="<?php echo htmlspecialchars($q); ?>" placeholder="last or first name" style="width:60%">
    <button type="submit">Search</button>
  </form>
</div>
<?php if ($ran): ?>
<div class="card">
  <table>
    <tr><th>ID</th><th>National ID</th><th>First</th><th>Last</th><th>DOB</th><th>Phone</th><th>Blood</th></tr>
    <?php foreach ($rows as $r): ?>
    <tr>
      <td><?php echo htmlspecialchars((string)$r['patient_id']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['national_id']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['first_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['last_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['date_of_birth']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['phone']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['blood_type']); ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <p style="font-size:12px;color:#667"><?php echo count($rows); ?> row(s). Columns returned: 7 (useful for UNION-based injection).</p>
</div>
<?php endif; ?>
<?php require_once __DIR__ . '/footer.php'; ?>
