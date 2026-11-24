<?php
/* =====================================================================
 *  Hardened session + security headers  (Phase 11)
 *  Include at the very top of every authenticated page (before output).
 * ===================================================================== */

function secure_session_start(): void {
    if (session_status() !== PHP_SESSION_NONE) { return; }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => $https,     // cookie only over TLS
        'httponly' => true,       // not readable by JavaScript (anti-XSS theft)
        'samesite' => 'Strict',   // not sent cross-site (anti-CSRF)
    ]);
    session_name('HRS_SID');
    session_start();

    $now = time();
    // absolute lifetime 8h, idle timeout 20min
    if ((isset($_SESSION['_created']) && $now - $_SESSION['_created'] > 8 * 3600)
     || (isset($_SESSION['_last'])    && $now - $_SESSION['_last']    > 20 * 60)) {
        $_SESSION = [];
        session_destroy();
        session_start();
    }
    $_SESSION['_created'] = $_SESSION['_created'] ?? $now;
    $_SESSION['_last']    = $now;
}

function send_security_headers(): void {
    header("Content-Security-Policy: default-src 'self'");
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
}
