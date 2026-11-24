<?php
/* Application-side audit logging (Phase 7). Records security-relevant events.
   Fails safe: if the audit table is not present yet, it never breaks the app. */
require_once __DIR__ . '/db.php';

/* Tell the DB which human user is acting, so triggers can log it
   (COALESCE(@app_user, CURRENT_USER())). Call once per authenticated request. */
function set_db_actor(?string $username): void {
    try {
        $stmt = db()->prepare('SET @app_user = ?');
        $stmt->execute([$username]);
    } catch (Throwable $e) {
        error_log('set_db_actor failed: ' . $e->getMessage());
    }
}

function log_event(?int $uid, ?string $username, string $action,
                   ?string $resource = null, ?string $resId = null,
                   bool $success = true, ?array $details = null): void {
    try {
        db()->prepare(
            'INSERT INTO audit_log
                (app_user_id, username, action, resource, resource_id,
                 success, ip_address, user_agent, details)
             VALUES (?,?,?,?,?,?,?,?,?)'
        )->execute([
            $uid, $username, $action, $resource, $resId,
            $success ? 1 : 0,
            $_SERVER['REMOTE_ADDR'] ?? null,
            substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255),
            $details !== null ? json_encode($details) : null,
        ]);
    } catch (Throwable $e) {
        error_log('audit insert failed: ' . $e->getMessage());
    }
}
