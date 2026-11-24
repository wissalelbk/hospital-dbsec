<?php
/* =====================================================================
 *  TOTP (RFC 6238) — MFA for privileged accounts  (Phase 11)
 *  Time-based one-time passwords, HMAC-SHA1, 30-second step, 6 digits,
 *  compatible with Google Authenticator / FreeOTP / Aegis.
 *  The per-user secret is stored AES-GCM encrypted (crypto.php).
 * ===================================================================== */

function base32_decode(string $b32): string {
    $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $b32 = strtoupper(str_replace('=', '', trim($b32)));
    $bits = '';
    foreach (str_split($b32) as $c) {
        $v = strpos($map, $c);
        if ($v === false) { continue; }
        $bits .= str_pad(decbin($v), 5, '0', STR_PAD_LEFT);
    }
    $out = '';
    foreach (str_split($bits, 8) as $byte) {
        if (strlen($byte) === 8) { $out .= chr(bindec($byte)); }
    }
    return $out;
}

function totp_code(string $secretB32, ?int $t = null, int $step = 30, int $digits = 6): string {
    $t = $t ?? time();
    $counter = intdiv($t, $step);
    $bin = "\x00\x00\x00\x00" . pack('N', $counter);           // 8-byte big-endian counter
    $hash = hash_hmac('sha1', $bin, base32_decode($secretB32), true);
    $off = ord($hash[strlen($hash) - 1]) & 0x0f;
    $code = ((ord($hash[$off]) & 0x7f) << 24)
          | ((ord($hash[$off + 1]) & 0xff) << 16)
          | ((ord($hash[$off + 2]) & 0xff) << 8)
          |  (ord($hash[$off + 3]) & 0xff);
    return str_pad((string)($code % (10 ** $digits)), $digits, '0', STR_PAD_LEFT);
}

/** Verify a code, tolerating ±$window steps of clock drift. Constant-time compare. */
function totp_verify(string $secretB32, string $code, int $window = 1): bool {
    $t = time();
    for ($i = -$window; $i <= $window; $i++) {
        if (hash_equals(totp_code($secretB32, $t + $i * 30), $code)) { return true; }
    }
    return false;
}

/** Generate a new base32 secret (default 160 bits). */
function totp_secret_new(int $bytes = 20): string {
    $map = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $bits = '';
    foreach (str_split(random_bytes($bytes)) as $c) {
        $bits .= str_pad(decbin(ord($c)), 8, '0', STR_PAD_LEFT);
    }
    $s = '';
    foreach (str_split($bits, 5) as $chunk) {
        $s .= $map[bindec(str_pad($chunk, 5, '0'))];
    }
    return $s;
}

/** otpauth:// provisioning URI for QR codes. */
function totp_uri(string $secretB32, string $account, string $issuer = 'Rabat General Hospital'): string {
    return 'otpauth://totp/' . rawurlencode($issuer . ':' . $account)
         . '?secret=' . $secretB32 . '&issuer=' . rawurlencode($issuer) . '&period=30&digits=6';
}
