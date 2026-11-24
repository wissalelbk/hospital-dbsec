-- =====================================================================
--  Phase 15 — Hardening complémentaire (v2)
--  Limites de ressources par compte (anti-DoS côté SGBD), réduction de la
--  divulgation de schéma, et durcissement TLS mutual-auth.
-- =====================================================================
USE hospital;

-- Limites de ressources sur le compte applicatif (empêche l'épuisement)
ALTER USER 'app_svc'@'192.168.56.20'
    WITH MAX_USER_CONNECTIONS 20
         MAX_QUERIES_PER_HOUR 50000
         MAX_UPDATES_PER_HOUR 20000;

-- Exiger un certificat client (mutual TLS) pour le compte applicatif
ALTER USER 'app_svc'@'192.168.56.20' REQUIRE X509;

-- Fichier de configuration (/etc/mysql/mysql.conf.d/mysqld.cnf) :
--   [mysqld]
--   skip_show_database        = ON      # un compte sans SHOW DATABASES priv ne liste pas les bases
--   max_connections           = 150
--   max_connect_errors        = 20      # bloque un hôte après trop d'erreurs de connexion
--   tls_version               = TLSv1.2,TLSv1.3
--   require_secure_transport  = ON
--   ssl_ca   = /etc/mysql/ssl/ca.pem
--   ssl_cert = /etc/mysql/ssl/server-cert.pem
--   ssl_key  = /etc/mysql/ssl/server-key.pem
