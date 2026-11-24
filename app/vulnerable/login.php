<?php
/* =====================================================================
 *  VULNERABLE login  (Vuln A: SQL injection + Vuln B: plaintext password)
 *
 *  Root causes embedded on purpose:
 *   1. User input concatenated directly into the SQL string (no prepared
 *      statement, no escaping)  → authentication bypass & injection.
 *   2. Password compared as PLAINTEXT against app_users.password_hash.
 *   3. mysqli_error() echoed on failure → leaks query to the attacker.
 *   4. No failed-attempt throttling / lockout.
 * ===================================================================== */
require_once __DIR__ . '/db.php';
session_start();
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // ⚠⚠ DANGEROUS: direct interpolation of untrusted input
    $sql = "SELECT u.user_id, u.username, r.role_name
            FROM app_users u
            JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = '$username'
              AND u.password_hash = '$password'";

    $res = mysqli_query($conn, $sql);
    if (!$res) {
        // ⚠ verbose error aids blind/UNION injection
        die('Query error: ' . mysqli_error($conn));
    }

    if (mysqli_num_rows($res) > 0) {
        $row = mysqli_fetch_assoc($res);
        $_SESSION['user'] = $row['username'];
        $_SESSION['role'] = $row['role_name'];
        header('Location: dashboard.php');
        exit;
    }
    $error = 'Invalid credentials';
}
require_once __DIR__ . '/header.php';
?>
<div class="card" style="max-width:360px;margin:40px auto">
  <h2>Staff / Patient Login</h2>
  <?php if ($error): ?><p class="err"><?php echo $error; ?></p><?php endif; ?>
  <form method="post" action="login.php">
    <p><input name="username" placeholder="username" style="width:100%"></p>
    <p><input name="password" type="password" placeholder="password" style="width:100%"></p>
    <p><button type="submit">Sign in</button></p>
  </form>
  <p style="font-size:12px;color:#667">Lab accounts: admin / dr.amrani / nurse.hajar / reception / billing / p.alaoui</p>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
