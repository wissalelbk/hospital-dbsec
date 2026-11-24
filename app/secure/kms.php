<?php
/* =====================================================================
 *  Envelope encryption + key management  (Phase 18, v3)
 *  Two-tier keys:
 *    - KEK (Key-Encryption-Key): a master key kept OFFLINE in a file.
 *    - DEK (Data-Encryption-Key): a random key that actually encrypts the
 *      data; it is stored WRAPPED (AES-GCM encrypted under the KEK) in the
 *      crypto_keys table, with a version.
 *  Benefits:
 *    - KEK rotation  = re-wrap the DEK only (no data re-encryption).
 *    - DEK rotation  = new versioned DEK; old data still decrypts via its
 *      version tag; new data uses the new DEK.
 *  Each ciphertext is self-describing:  [version:1][IV:12][tag:16][ct].
 * ===================================================================== */
require_once __DIR__ . '/db.php';

function kek(): string {
    $p = getenv('APP_KEK_FILE') ?: (defined('APP_KEK_FILE') ? APP_KEK_FILE : '/etc/hospital/kek.key');
    $k = @file_get_contents($p);
    if ($k === false || strlen($k) < 32) { throw new RuntimeException('KEK unavailable'); }
    return substr($k, 0, 32);
}

function aes_wrap(string $plain, string $key): string {
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    return $iv . $tag . $ct;
}
function aes_unwrap(string $blob, string $key): ?string {
    $iv = substr($blob,0,12); $tag = substr($blob,12,16); $ct = substr($blob,28);
    $pt = openssl_decrypt($ct, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
    return $pt === false ? null : $pt;
}

/** Load (and cache) a DEK by version: unwrap the stored DEK with the KEK. */
function load_dek(int $version): string {
    static $cache = [];
    if (isset($cache[$version])) { return $cache[$version]; }
    $st = db()->prepare('SELECT wrapped_dek FROM crypto_keys WHERE version=?');
    $st->execute([$version]);
    $w = $st->fetchColumn();
    if ($w === false) { throw new RuntimeException("DEK v$version not found"); }
    $dek = aes_unwrap($w, kek());
    if ($dek === null) { throw new RuntimeException('DEK unwrap failed (wrong KEK?)'); }
    return $cache[$version] = $dek;
}

function active_dek(): array {
    $row = db()->query('SELECT version FROM crypto_keys WHERE is_active=1 ORDER BY version DESC LIMIT 1')->fetch();
    if (!$row) { throw new RuntimeException('no active DEK'); }
    return [(int)$row['version'], load_dek((int)$row['version'])];
}

/** Envelope-encrypt with the active DEK; ciphertext carries its DEK version. */
function enc_env(string $plain): string {
    [$v, $dek] = active_dek();
    return pack('C', $v) . aes_wrap($plain, $dek);
}
function dec_env(string $blob): ?string {
    $v = ord($blob[0]);
    return aes_unwrap(substr($blob,1), load_dek($v));
}

/* ---------------- key lifecycle ---------------- */

/** Create the first DEK (version 1) if none exists. */
function kms_init(): void {
    $n = (int)db()->query('SELECT COUNT(*) FROM crypto_keys')->fetchColumn();
    if ($n === 0) {
        $dek = random_bytes(32);
        db()->prepare('INSERT INTO crypto_keys (version, wrapped_dek, is_active) VALUES (1,?,1)')
            ->execute([aes_wrap($dek, kek())]);
    }
}

/** KEK rotation: re-wrap every DEK under a NEW KEK. No data is re-encrypted. */
function rotate_kek(string $new_kek): void {
    $pdo = db();
    foreach ($pdo->query('SELECT key_id, wrapped_dek FROM crypto_keys')->fetchAll() as $r) {
        $dek = aes_unwrap($r['wrapped_dek'], kek());
        $pdo->prepare('UPDATE crypto_keys SET wrapped_dek=? WHERE key_id=?')
            ->execute([aes_wrap($dek, $new_kek), $r['key_id']]);
    }
}

/** DEK rotation: new active versioned DEK; old DEKs retained for decryption. */
function rotate_dek(): int {
    $pdo = db();
    $v = (int)$pdo->query('SELECT COALESCE(MAX(version),0)+1 FROM crypto_keys')->fetchColumn();
    $dek = random_bytes(32);
    $pdo->exec('UPDATE crypto_keys SET is_active=0');
    $pdo->prepare('INSERT INTO crypto_keys (version, wrapped_dek, is_active) VALUES (?,?,1)')
        ->execute([$v, aes_wrap($dek, kek())]);
    return $v;
}
