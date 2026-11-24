<?php
/* =====================================================================
 *  VULNERABLE medical record view
 *   - Vuln A : $_GET['patient_id'] concatenated into the query (SQLi).
 *   - IDOR   : no check that the logged-in user may see THIS patient;
 *              a patient account can read anyone's record by changing the id.
 *   - Vuln D : diagnosis / clinical notes / lab values shown in clear.
 * ===================================================================== */
require_once __DIR__ . '/header.php';
if (empty($_SESSION['user'])) { header('Location: login.php'); exit; }
require_once __DIR__ . '/db.php';

$pid = $_GET['patient_id'] ?? '1';

// ⚠⚠ DANGEROUS: no authorization check, no parameterization
$sql = "SELECT p.first_name, p.last_name, p.national_id,
               m.visit_date, m.diagnosis, m.treatment, m.clinical_notes,
               s.full_name AS doctor
        FROM medical_records m
        JOIN patients p ON p.patient_id = m.patient_id
        JOIN staff s    ON s.staff_id   = m.doctor_staff_id
        WHERE m.patient_id = $pid
        ORDER BY m.visit_date DESC";
$res = mysqli_query($conn, $sql);
?>
<div class="card">
  <h2>Medical records — patient #<?php echo htmlspecialchars((string)$pid); ?></h2>
  <?php if (!$res): ?>
    <p class="err">Query error: <?php echo mysqli_error($conn); ?></p>
  <?php else: ?>
  <table>
    <tr><th>Patient</th><th>National ID</th><th>Visit</th><th>Diagnosis</th><th>Treatment</th><th>Clinical notes</th><th>Doctor</th></tr>
    <?php while ($r = mysqli_fetch_assoc($res)): ?>
    <tr>
      <td><?php echo htmlspecialchars($r['first_name'].' '.$r['last_name']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['national_id']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['visit_date']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['diagnosis']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['treatment']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['clinical_notes']); ?></td>
      <td><?php echo htmlspecialchars((string)$r['doctor']); ?></td>
    </tr>
    <?php endwhile; ?>
  </table>
  <p style="font-size:12px;color:#b00020">Try changing <code>?patient_id=</code> — nothing stops you reading another patient (IDOR).</p>
  <?php endif; ?>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
