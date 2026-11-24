<?php
/* =====================================================================
 *  Sensitive-data encryption at rest  (Phase 6)
 *  AES-256-GCM (authenticated encryption) applied application-side to the
 *  most sensitive columns: national_id, insurance_policy_no, clinical_notes.
 *
 *  KEY MANAGEMENT (justified in docs/phase6-sensitive-data.md):
 *   - 32-byte key kept OUTSIDE the database and OUTSIDE the code, in a file
 *     readable only by the app user (chmod 600), path in APP_KEY_FILE.
 *   - Generate once on app-vm:
 *       mkdir -p /etc/hospital && head -c 32 /dev/urandom > /etc/hospital/app.key
 *       chmod 600 /etc/hospital/app.key && chown www-data /etc/hospital/app.key
 *   - Rotation: decrypt-with-old / re-encrypt-with-new; GCM tag detects tampering.
 *
 *  Storage layout per value (raw bytes in a VARBINARY column):
 *      [ 12-byte IV/nonce ][ 16-byte GCM tag ][ ciphertext ]
 * ===================================================================== */

function app_key(): string {
    $path = getenv('APP_KEY_FILE') ?: (defined('APP_KEY_FILE') ? APP_KEY_FILE : '/etc/hospital/app.key');
    $key = @file_get_contents($path);
    if ($key === false || strlen($key) < 32) {
        throw new RuntimeException('Encryption key unavailable or too short');
    }
    return substr($key, 0, 32);               // AES-256 → 32-byte key
}

function enc(?string $plain): ?string {
    if ($plain === null) { return null; }
    $iv  = random_bytes(12);
    $tag = '';
    $ct  = openssl_encrypt($plain, 'aes-256-gcm', app_key(), OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ct === false) { throw new RuntimeException('Encryption failed'); }
    return $iv . $tag . $ct;
}

function dec(?string $blob): ?string {
    if ($blob === null || strlen($blob) < 28) { return null; }
    $iv  = substr($blob, 0, 12);
    $tag = substr($blob, 12, 16);
    $ct  = substr($blob, 28);
    $pt  = openssl_decrypt($ct, 'aes-256-gcm', app_key(), OPENSSL_RAW_DATA, $iv, $tag);
    return $pt === false ? null : $pt;        // false ⇒ wrong key or tampered (GCM auth fail)
}
