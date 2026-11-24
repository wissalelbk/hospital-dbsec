<?php
/* SECURE patient search — fixes baseline Vuln A (SQLi) and Vuln D (clear PII).
 *  - PREPARED STATEMENT with a bound LIKE parameter (injection-proof)
 *  - server-side RBAC (accountant/patient cannot search all patients)
 *  - national_id is decrypted for display and masked for non-clinical roles
 */
require_once __DIR__ . '/header.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/audit.php';

$cu = require_role(['DBA', 'Doctor', 'Nurse', 'Receptionist']);
$canSeeFullId = in_array($cu['role'], ['DBA', 'Doctor', 'Nurse'], true);

$q = $_GET['q'] ?? '';
$rows = [];
if ($q !== '') {
    // ✅ bound parameter — user input is DATA, never SQL
    $stmt = db()->prepare(
        'SELECT patient_id, national_id, first_name, last_name,
                date_of_birth, phone, blood_type
           FROM patients
          WHERE last_name LIKE :term1 OR first_name LIKE :term2
          ORDER BY last_name'
    );
    $term = '%' . $q . '%';
    $stmt->execute([':term1' => $term, ':term2' => $term]);
    $rows = $stmt->fetchAll();
    log_event($cu['uid'], $cu['username'], 'PATIENT_SEARCH', 'patients', null, true, ['q' => $q]);
}
?>
<div class="card">
  <h2>Patient search</h2>
  <form method="get" action="search.php">
    <input name="q" value="<?php echo htmlspecialchars($q); ?>" placeholder="last or first name" style="width:60%">
    <button type="submit">Search</button>
  </form>
</div>
<?php if ($q !== ''): ?>
<div class="card">
  <table>
    <tr><th>ID</th><th>National ID</th><th>First</th><th>Last</th><th>DOB</th><th>Phone</th><th>Blood</th></tr>
    <?php foreach ($rows as $r):
        $nid = dec($r['national_id']);                 // decrypt for display
        $nid = $canSeeFullId ? (string)$nid : mask_id($nid);
    ?>
    <tr>
      <td><?php echo (int)$r['patient_id']; ?></td>
      <td><?php echo htmlspecialchars($nid); ?></td>
      <td><?php echo htmlspecialchars((string)$r['first_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['last_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['date_of_birth']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['phone']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['blood_type']); ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <p style="font-size:12px;color:#667"><?php echo count($rows); ?> row(s).</p>
</div>
<?php endif; ?>
<?php require_once __DIR__ . '/footer.php'; ?>
