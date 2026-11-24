<?php
/* =====================================================================
 *  SECURE authentication  (Phase 3)
 *  Fixes the baseline login vulnerabilities:
 *   - PREPARED STATEMENT (bound param) → no SQL injection
 *   - password_verify() against an Argon2id hash → no plaintext compare
 *   - account LOCKOUT after repeated failures
 *   - transparent REHASH if parameters/algorithm changed
 *   - session fixation protection (regenerate id on login)
 * ===================================================================== */
require_once __DIR__ . '/db.php';

/**
 * Attempt login. Returns the user row on success, or null on failure.
 * Never reveals whether the username or the password was wrong.
 */
function attempt_login(string $username, string $password): ?array {
    $pdo = db();

    // 1) Look the user up with a PREPARED STATEMENT (injection-proof).
    $stmt = $pdo->prepare(
        'SELECT u.user_id, u.username, u.password_hash, u.role_id, r.role_name,
                u.is_active, u.failed_attempts, u.locked_until,
                u.staff_id, u.patient_id
           FROM app_users u
           JOIN roles r ON r.role_id = u.role_id
          WHERE u.username = ?'
    );
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    // 2) Uniform handling for "no such user" (avoid user enumeration + timing).
    if (!$user || !$user['is_active']) {
        // still spend time so response timing doesn't leak existence
        password_verify($password, '$argon2id$v=19$m=65536,t=3,p=1$'
            . base64_encode(random_bytes(16)) . '$' . base64_encode(random_bytes(32)));
        return null;
    }

    // 3) Enforce lockout window.
    if ($user['locked_until'] !== null && strtotime($user['locked_until']) > time()) {
        return null; // locked
    }

    // 4) Verify the password against the Argon2id hash.
    if (!password_verify($password, $user['password_hash'])) {
        register_failed_attempt($user);
        return null;
    }

    // 5) Success: reset counters, update last_login, rehash if needed.
    if (password_needs_rehash($user['password_hash'], PASSWORD_ARGON2ID, ARGON_OPTS)) {
        $new = password_hash($password, PASSWORD_ARGON2ID, ARGON_OPTS);
        $pdo->prepare('UPDATE app_users SET password_hash=? WHERE user_id=?')
            ->execute([$new, $user['user_id']]);
    }
    $pdo->prepare('UPDATE app_users
                      SET failed_attempts=0, locked_until=NULL, last_login_at=NOW()
                    WHERE user_id=?')->execute([$user['user_id']]);

    // Session fixation protection (web context only)
    if (PHP_SAPI !== 'cli' && !headers_sent()) {
        if (session_status() === PHP_SESSION_NONE) { session_start(); }
        session_regenerate_id(true);
    }

    unset($user['password_hash']);
    return $user;
}

function register_failed_attempt(array $user): void {
    $pdo = db();
    $attempts = (int)$user['failed_attempts'] + 1;
    if ($attempts >= MAX_FAILED_ATTEMPTS) {
        $pdo->prepare('UPDATE app_users
                          SET failed_attempts=?, locked_until=DATE_ADD(NOW(), INTERVAL ? MINUTE)
                        WHERE user_id=?')
            ->execute([$attempts, LOCKOUT_MINUTES, $user['user_id']]);
    } else {
        $pdo->prepare('UPDATE app_users SET failed_attempts=? WHERE user_id=?')
            ->execute([$attempts, $user['user_id']]);
    }
}

/** Create/replace a user's password with a fresh Argon2id hash. */
function set_password(int $user_id, string $password): void {
    $hash = password_hash($password, PASSWORD_ARGON2ID, ARGON_OPTS);
    db()->prepare('UPDATE app_users SET password_hash=?, password_changed_at=NOW() WHERE user_id=?')
        ->execute([$hash, $user_id]);
}
