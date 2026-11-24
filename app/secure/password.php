<?php
/* =====================================================================
 *  Password hashing v2 — server-side PEPPER + Argon2id  (Phase 11)
 *  A pepper is a secret kept OUTSIDE the database (like the AES key).
 *  Even if the whole DB (with Argon2id hashes) leaks, an attacker cannot
 *  mount an offline crack without also stealing the pepper from the app host.
 *
 *  Scheme (hash_version = 2):  Argon2id( HMAC-SHA256(pepper, password) )
 *  Legacy  (hash_version = 1):  Argon2id( password )   — still verified,
 *    then transparently upgraded to v2 on next successful login.
 * ===================================================================== */
if (!defined('ARGON_OPTS')) { require_once __DIR__ . '/config.php'; }

function app_pepper(): string {
    $path = getenv('APP_PEPPER_FILE') ?: (defined('APP_PEPPER_FILE') ? APP_PEPPER_FILE : '/etc/hospital/pepper.key');
    $p = @file_get_contents($path);
    if ($p === false || strlen($p) < 32) {
        throw new RuntimeException('Pepper unavailable or too short');
    }
    return $p;
}

/** Produce a v2 hash (pepper + Argon2id). */
function hash_password(string $pw): string {
    $pre = base64_encode(hash_hmac('sha256', $pw, app_pepper(), true));
    return password_hash($pre, PASSWORD_ARGON2ID, ARGON_OPTS);
}

/** Verify against either a v2 (peppered) or v1 (legacy) hash. */
function verify_password(string $pw, string $hash, int $version = 2): bool {
    if ($version >= 2) {
        $pre = base64_encode(hash_hmac('sha256', $pw, app_pepper(), true));
        return password_verify($pre, $hash);
    }
    return password_verify($pw, $hash);   // legacy, un-peppered
}
