<?php
/* =====================================================================
 *  One-off migration: encrypt existing plaintext in the sensitive columns.
 *  Run once on db-vm AFTER db/06_sensitive_data.sql:  php encrypt_sensitive.php
 *  Idempotent: a value that already decrypts under the key is skipped
 *  (GCM authentication makes a false "already encrypted" essentially impossible).
 * ===================================================================== */
require_once __DIR__ . '/db.php';
require_once __DIR__ . '/crypto.php';

$pdo = db();

$targets = [
    ['patients',        'patient_id', 'national_id'],
    ['billing',         'invoice_id', 'insurance_policy_no'],
    ['medical_records', 'record_id',  'clinical_notes'],
];

foreach ($targets as [$table, $pk, $col]) {
    $rows = $pdo->query("SELECT $pk AS id, $col AS val FROM $table")->fetchAll();
    $n = 0;
    foreach ($rows as $r) {
        if ($r['val'] === null) { continue; }
        if (dec($r['val']) !== null) { continue; }      // already ciphertext → skip
        $stmt = $pdo->prepare("UPDATE $table SET $col = ? WHERE $pk = ?");
        $stmt->execute([enc((string)$r['val']), $r['id']]);
        $n++;
    }
    echo "Encrypted $n value(s) in $table.$col\n";
}
