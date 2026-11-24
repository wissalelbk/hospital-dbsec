<?php
require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/audit.php';
if (session_status() === PHP_SESSION_NONE) { session_start(); }
$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';
    $user = attempt_login($username, $password);   // prepared stmt + Argon2id + lockout
    if ($user) {
        $_SESSION['uid']        = $user['user_id'];
        $_SESSION['username']   = $user['username'];
        $_SESSION['role']       = $user['role_name'];
        $_SESSION['staff_id']   = $user['staff_id'];
        $_SESSION['patient_id'] = $user['patient_id'];
        log_event($user['user_id'], $user['username'], 'LOGIN_SUCCESS');
        header('Location: dashboard.php');
        exit;
    }
    // Generic message — never reveal whether user or password was wrong
    log_event(null, $username, 'LOGIN_FAIL', null, null, false);
    $error = 'Invalid credentials';
}
require_once __DIR__ . '/header.php';
?>
<div class="card" style="max-width:360px;margin:40px auto">
  <h2>Staff / Patient Login</h2>
  <?php if ($error): ?><p class="err"><?php echo htmlspecialchars($error); ?></p><?php endif; ?>
  <form method="post" action="login.php" autocomplete="off">
    <p><input name="username" placeholder="username" style="width:100%"></p>
    <p><input name="password" type="password" placeholder="password" style="width:100%"></p>
    <p><button type="submit">Sign in</button></p>
  </form>
</div>
<?php require_once __DIR__ . '/footer.php'; ?>
