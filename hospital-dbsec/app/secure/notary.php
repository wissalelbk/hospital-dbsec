<?php
require_once __DIR__ . '/db.php';
function audit_key(): string {
    $p=getenv('APP_AUDIT_KEY_FILE')?:(defined('APP_AUDIT_KEY_FILE')?APP_AUDIT_KEY_FILE:'/etc/hospital/audit.key');
    $k=@file_get_contents($p); if($k===false||strlen($k)<32) throw new RuntimeException('audit key unavailable');
    return $k;
}
function notarize(): void {
    $r=db()->query("SELECT log_id,row_hash FROM audit_log ORDER BY log_id DESC LIMIT 1")->fetch();
    if(!$r) return;
    $sig=hash_hmac('sha256',$r['log_id'].'|'.bin2hex($r['row_hash']),audit_key(),true);
    db()->prepare("INSERT INTO audit_notary (upto_log_id,chain_hash,hmac_sig) VALUES (?,?,?)")
        ->execute([$r['log_id'],$r['row_hash'],$sig]);
}
function verify_notary(): array {
    $n=db()->query("SELECT upto_log_id,chain_hash,hmac_sig FROM audit_notary ORDER BY notary_id DESC LIMIT 1")->fetch();
    if(!$n) return ['ok'=>true,'reason'=>'aucune notarisation'];
    $expect=hash_hmac('sha256',$n['upto_log_id'].'|'.bin2hex($n['chain_hash']),audit_key(),true);
    if(!hash_equals($expect,$n['hmac_sig'])) return ['ok'=>false,'reason'=>'signature de notarisation invalide'];
    $c=db()->prepare("SELECT row_hash FROM audit_log WHERE log_id=?"); $c->execute([$n['upto_log_id']]);
    $cur=$c->fetchColumn();
    if($cur===false) return ['ok'=>false,'reason'=>'ligne notarisée supprimée'];
    if(!hash_equals($n['chain_hash'],$cur)) return ['ok'=>false,'reason'=>'tip de chaîne modifié depuis la notarisation'];
    return ['ok'=>true,'reason'=>'intègre'];
}
