-- =====================================================================
--  Phase 18 (v3) — Key management: wrapped data keys (envelope encryption)
-- =====================================================================
USE hospital;
CREATE TABLE IF NOT EXISTS crypto_keys (
    key_id      INT AUTO_INCREMENT PRIMARY KEY,
    version     INT NOT NULL UNIQUE,
    wrapped_dek VARBINARY(128) NOT NULL,   -- DEK wrapped (AES-GCM) under the KEK
    is_active   TINYINT(1) NOT NULL DEFAULT 0,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
