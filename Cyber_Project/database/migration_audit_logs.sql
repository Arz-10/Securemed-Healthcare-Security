-- ================================================================
-- migration_audit_logs.sql – Additive migration for security audit logs
-- Run this against securemed_db to create the audit_logs table.
-- ================================================================

USE securemed_db;

CREATE TABLE IF NOT EXISTS audit_logs (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    user_id     INT UNSIGNED    NULL,
    event_type  VARCHAR(50)     NOT NULL,
    outcome     VARCHAR(20)     NOT NULL,
    ip_address  VARCHAR(45)     NULL,
    details     VARCHAR(255)    NULL,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_audit_user (user_id),
    INDEX idx_audit_event (event_type),
    INDEX idx_audit_created (created_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
