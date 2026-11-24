<?php
/* =====================================================================
 *  Login throttling  (Phase 11)  — defeats brute force AND the
 *  account-lockout denial-of-service that a naive per-account lock creates.
 *
 *  Design:
 *   - The PRIMARY brake is per-IP: an attacker flooding from one host is
 *     blocked by IP, so they cannot lock out a victim's account at will.
 *   - A SECONDARY per-account soft counter still exists, but because the
 *     IP brake trips first, a legitimate user from a different IP keeps
 *     working even while an attacker hammers their username.
 * ===================================================================== */
require_once __DIR__ . '/db.php';

/** Is this scope currently allowed to attempt? Returns [allowed, retry_after_s]. */
function throttle_check(string $scope, string $key): array {
    $pdo = db();
    $pdo->prepare('INSERT INTO login_throttle (scope, scope_key, window_start, attempts)
                   VALUES (?,?,NOW(),0) ON DUPLICATE KEY UPDATE id=id')->execute([$scope, $key]);
    $st = $pdo->prepare('SELECT window_start, attempts, blocked_until
                         FROM login_throttle WHERE scope=? AND scope_key=?');
    $st->execute([$scope, $key]);
    $r = $st->fetch();
    if ($r['blocked_until'] !== null && strtotime($r['blocked_until']) > time()) {
        return [false, strtotime($r['blocked_until']) - time()];
    }
    return [true, 0];
}

/** Record a failed attempt; block the scope once it exceeds $max within $windowSec. */
function throttle_fail(string $scope, string $key, int $max, int $windowSec, int $blockSec): void {
    $pdo = db();
    // reset the window if it has expired
    $pdo->prepare('UPDATE login_throttle
                   SET attempts=0, blocked_until=NULL, window_start=NOW()
                   WHERE scope=? AND scope_key=? AND window_start + INTERVAL ? SECOND < NOW()')
        ->execute([$scope, $key, $windowSec]);
    $pdo->prepare('UPDATE login_throttle
                   SET attempts = attempts + 1,
                       blocked_until = IF(attempts + 1 >= ?, DATE_ADD(NOW(), INTERVAL ? SECOND), blocked_until)
                   WHERE scope=? AND scope_key=?')
        ->execute([$max, $blockSec, $scope, $key]);
}

/** Clear counters after a successful login. */
function throttle_reset(string $scope, string $key): void {
    db()->prepare('UPDATE login_throttle SET attempts=0, blocked_until=NULL WHERE scope=? AND scope_key=?')
        ->execute([$scope, $key]);
}
