<?php
/* Server-side authorization helpers (Phase 2 enforcement in the app layer).
   Fixes the baseline weakness where every link worked for every role. */

function current_user(): ?array {
    if (session_status() === PHP_SESSION_NONE) { session_start(); }
    return empty($_SESSION['uid']) ? null : [
        'uid'        => $_SESSION['uid'],
        'username'   => $_SESSION['username'],
        'role'       => $_SESSION['role'],
        'staff_id'   => $_SESSION['staff_id']   ?? null,
        'patient_id' => $_SESSION['patient_id'] ?? null,
    ];
}

function require_login(): array {
    $u = current_user();
    if ($u === null) { header('Location: login.php'); exit; }
    return $u;
}

/** Enforce that the logged-in user holds one of the allowed roles. */
function require_role(array $allowed): array {
    $u = require_login();
    if (!in_array($u['role'], $allowed, true)) {
        require_once __DIR__ . '/audit.php';
        log_event($u['uid'], $u['username'], 'AUTHZ_DENIED', $_SERVER['SCRIPT_NAME'] ?? null, null, false);
        http_response_code(403);
        echo '403 — You do not have permission to access this resource.';
        exit;
    }
    return $u;
}

/** Mask a national ID for roles that may see a record but not the full ID. */
function mask_id(?string $v): string {
    if ($v === null || $v === '') { return ''; }
    $n = strlen($v);
    return $n <= 2 ? str_repeat('*', $n) : str_repeat('*', $n - 2) . substr($v, -2);
}
