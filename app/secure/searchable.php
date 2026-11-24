<?php
/* =====================================================================
 *  Blind index (searchable encryption)  (Phase 13)
 *  Randomized AES-GCM protects national_id at rest, but it destroys the
 *  ability to (a) enforce uniqueness and (b) look a patient up by exact
 *  national_id. A BLIND INDEX restores both WITHOUT revealing plaintext:
 *
 *    bidx = HMAC-SHA256( blind_index_key , normalize(value) )
 *
 *  - Deterministic → equal national_ids yield equal bidx → a UNIQUE index
 *    on the bidx column re-enforces uniqueness over encrypted data.
 *  - Exact-match lookup: compute the bidx of the query and filter on it.
 *  - One-way + keyed → the index leaks neither the plaintext nor equality
 *    to anyone without the key.
 *  The blind-index key is SEPARATE from the AES key (key separation).
 * ===================================================================== */

function blind_index_key(): string {
    $path = getenv('APP_BIDX_FILE') ?: (defined('APP_BIDX_FILE') ? APP_BIDX_FILE : '/etc/hospital/bidx.key');
    $k = @file_get_contents($path);
    if ($k === false || strlen($k) < 32) {
        throw new RuntimeException('Blind-index key unavailable');
    }
    return $k;
}

function normalize_value(string $v): string {
    return strtoupper(preg_replace('/\s+/', '', trim($v)));   // case/space-insensitive match
}

/** 32-byte raw HMAC blind index for a value. */
function blind_index(string $value): string {
    return hash_hmac('sha256', normalize_value($value), blind_index_key(), true);
}
