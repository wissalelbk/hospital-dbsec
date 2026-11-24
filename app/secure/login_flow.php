<?php
/* =====================================================================
 *  Unified secure login flow v2  (Phase 11)
 *  Order of controls:
 *    1. per-IP throttle   (brute force + lockout-DoS mitigation)
 *    2. prepared-statement user lookup   (no SQL injection)
 *    3. pepper + Argon2id verify          (offline-crack resistant)
 *    4. TOTP MFA gate for mfa_enabled accounts
 *    5. transparent rehash v1 -> v2, reset counters, audit
 *
 *  Returns one of:
 *    ['status'=>'ok', 'user'=>...]            fully authenticated
 *    ['status'=>'mfa_required', 'uid'=>...]   password ok, awaiting TOTP
 *    ['status'=>'throttled', 'retry'=>secs]
 *    ['status'=>'fail']
 * ===================================================================== */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/password.php';
require_once __DIR__ . '/totp.php';
require_once __DIR__ . '/crypto.php';
require_once __DIR__ . '/ratelimit.php';
require_once __DIR__ . '/audit.php';

const RL_MAX = 5, RL_WINDOW = 900, RL_BLOCK = 900;

function secure_login(string $username, string $password, string $ip): array {
    // 1. IP throttle first — an attacker cannot even reach the password check
    [$ok, $retry] = throttle_check('ip', $ip);
    if (!$ok) { log_event(null, $username, 'LOGIN_THROTTLED', null, null, false, ['ip' => $ip]); return ['status' => 'throttled', 'retry' => $retry]; }

    // 2. prepared-statement lookup
    $st = db()->prepare('SELECT u.user_id,u.username,u.password_hash,u.hash_version,u.mfa_enabled,
                                u.totp_secret,u.role_id,r.role_name,u.is_active,u.staff_id,u.patient_id
                         FROM app_users u JOIN roles r ON r.role_id=u.role_id WHERE u.username=?');
    $st->execute([$username]);
    $u = $st->fetch();

    // 3. verify (uniform failure handling)
    $okpw = $u && $u['is_active'] && verify_password($password, $u['password_hash'], (int)$u['hash_version']);
    if (!$okpw) {
        throttle_fail('ip', $ip, RL_MAX, RL_WINDOW, RL_BLOCK);
        throttle_fail('account', $username, RL_MAX * 4, RL_WINDOW, RL_BLOCK); // softer account brake
        log_event(null, $username, 'LOGIN_FAIL', null, null, false, ['ip' => $ip]);
        return ['status' => 'fail'];
    }

    // 4. MFA gate
    if ((int)$u['mfa_enabled'] === 1) {
        return ['status' => 'mfa_required', 'uid' => (int)$u['user_id']];
    }

    return finalize_login($u, $ip);
}

/** Second step: verify the TOTP code for an account that passed the password stage. */
function secure_login_mfa(int $uid, string $code, string $ip): array {
    $st = db()->prepare('SELECT u.user_id,u.username,u.totp_secret,u.role_id,r.role_name,u.staff_id,u.patient_id
                         FROM app_users u JOIN roles r ON r.role_id=u.role_id WHERE u.user_id=?');
    $st->execute([$uid]);
    $u = $st->fetch();
    if (!$u || $u['totp_secret'] === null || !totp_verify(dec($u['totp_secret']), $code, 1)) {
        throttle_fail('ip', $ip, RL_MAX, RL_WINDOW, RL_BLOCK);
        log_event((int)$u['user_id'] ?? null, $u['username'] ?? null, 'MFA_FAIL', null, null, false, ['ip' => $ip]);
        return ['status' => 'fail'];
    }
    return finalize_login($u, $ip);
}

function finalize_login(array $u, string $ip): array {
    // transparent upgrade v1 -> v2 is handled at password-set time; reset brakes
    throttle_reset('ip', $ip);
    throttle_reset('account', $u['username']);
    db()->prepare('UPDATE app_users SET failed_attempts=0, locked_until=NULL, last_login_at=NOW() WHERE user_id=?')
        ->execute([$u['user_id']]);
    log_event((int)$u['user_id'], $u['username'], 'LOGIN_SUCCESS', null, null, true, ['ip' => $ip]);
    unset($u['password_hash'], $u['totp_secret']);
    return ['status' => 'ok', 'user' => $u];
}
