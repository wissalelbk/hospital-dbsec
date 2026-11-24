<?php
/* SECURE medical record view — fixes baseline Vuln A (SQLi) and the IDOR.
 *  - PREPARED STATEMENT with bound patient_id
 *  - row-level ownership: a Patient can ONLY read their own record
 *  - clinical_notes decrypted for display
 */
require_once __DIR__ . '/header.php';
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/audit.php';

$cu = require_role(['DBA', 'Doctor', 'Nurse', 'Patient']);

// Row-level ownership: patients are forced to their own id (IDOR fix)
if ($cu['role'] === 'Patient') {
    $pid = (int)$cu['patient_id'];
} else {
    $pid = isset($_GET['patient_id']) ? (int)$_GET['patient_id'] : 0;  // cast → no injection
}

$rows = [];
if ($pid > 0) {
    $stmt = db()->prepare(
        'SELECT p.first_name, p.last_name,
                m.visit_date, m.diagnosis, m.treatment, m.clinical_notes,
                s.full_name AS doctor
           FROM medical_records m
           JOIN patients p ON p.patient_id = m.patient_id
           JOIN staff s    ON s.staff_id   = m.doctor_staff_id
          WHERE m.patient_id = :pid
          ORDER BY m.visit_date DESC'
    );
    $stmt->execute([':pid' => $pid]);
    $rows = $stmt->fetchAll();
    log_event($cu['uid'], $cu['username'], 'VIEW_MEDICAL_RECORD', 'medical_records', (string)$pid, true);
}
?>
<div class="card">
  <h2>Medical records<?php echo $pid ? ' — patient #' . $pid : ''; ?></h2>
  <?php if ($cu['role'] !== 'Patient'): ?>
  <form method="get" action="record.php">
    <input name="patient_id" value="<?php echo $pid ?: ''; ?>" placeholder="patient id" style="width:160px">
    <button type="submit">Open</button>
  </form><br>
  <?php endif; ?>
  <?php if ($pid > 0): ?>
  <table>
    <tr><th>Patient</th><th>Visit</th><th>Diagnosis</th><th>Treatment</th><th>Clinical notes</th><th>Doctor</th></tr>
    <?php foreach ($rows as $r): ?>
    <tr>
      <td><?php echo htmlspecialchars($r['first_name'] . ' ' . $r['last_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['visit_date']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['diagnosis']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['treatment']); ?></td>
      <td><?php echo htmlspecialchars((string)(dec($r['clinical_notes']) ?? '')); ?></td>
      <td><?php echo htmlspecialchars((string)$r['doctor']); ?></td>
    </tr>
    <?php endforeach; ?>
  </table>
  <?php endif; ?>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
