<?php
/* =====================================================================
 *  One-off migration: replace the baseline CLEARTEXT passwords in
 *  app_users with Argon2id hashes. Run once on db-vm after deploying
 *  the secure app:   php migrate_passwords.php
 *  (Idempotent: skips rows that are already PHC Argon2id strings.)
 * ===================================================================== */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/auth.php';

$pdo = db();
$rows = $pdo->query('SELECT user_id, password_hash FROM app_users')->fetchAll();

$migrated = 0;
foreach ($rows as $r) {
    if (str_starts_with((string)$r['password_hash'], '$argon2id$')) {
        continue; // already hashed
    }
    // The baseline stored the cleartext password in this column.
    set_password((int)$r['user_id'], (string)$r['password_hash']);
    $migrated++;
}
echo "Migrated {$migrated} password(s) to Argon2id.\n";
