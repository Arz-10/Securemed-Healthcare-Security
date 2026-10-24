-- ================================================================
-- schema.sql  –  SecureMed database schema
-- Run this once against your MySQL server to bootstrap the DB.
--
-- Usage (from project root):
--   mysql -u root -p < database/schema.sql
-- ================================================================

-- Create and select the database
CREATE DATABASE IF NOT EXISTS securemed_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE securemed_db;

-- ----------------------------------------------------------------
-- users  (shared across all roles)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    username    VARCHAR(80)     NOT NULL UNIQUE,
    password    VARCHAR(255)    NOT NULL,       -- Werkzeug hash
    role        ENUM('admin','doctor','patient') NOT NULL,
    full_name   VARCHAR(150)    NOT NULL,
    email       VARCHAR(150)    NOT NULL UNIQUE,
    phone       VARCHAR(20),
    is_active   TINYINT(1)      NOT NULL DEFAULT 1,
    created_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- doctors  (extends users for doctor-specific data)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS doctors (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED NOT NULL,
    specialisation  VARCHAR(100),
    licence_number  VARCHAR(60),
    department      VARCHAR(100),
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- patients  (extends users for patient-specific data)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS patients (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id         INT UNSIGNED NOT NULL,
    date_of_birth   DATE,
    gender          ENUM('male','female','other'),
    blood_group     VARCHAR(5),
    address         TEXT,
    emergency_contact VARCHAR(20),
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- appointments
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS appointments (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    doctor_id       INT UNSIGNED NOT NULL,
    appointment_date DATETIME    NOT NULL,
    reason          TEXT,
    status          ENUM('scheduled','completed','cancelled') NOT NULL DEFAULT 'scheduled',
    notes           TEXT,
    created_at      DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (patient_id) REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (doctor_id)  REFERENCES doctors(id)  ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- medical_records
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS medical_records (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    doctor_id       INT UNSIGNED NOT NULL,
    appointment_id  INT UNSIGNED,
    diagnosis       TEXT,
    prescription    TEXT,
    notes           TEXT,
    record_date     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (patient_id)    REFERENCES patients(id)      ON DELETE CASCADE,
    FOREIGN KEY (doctor_id)     REFERENCES doctors(id)       ON DELETE CASCADE,
    FOREIGN KEY (appointment_id)REFERENCES appointments(id)  ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- uploads  (medical reports / files)
-- ----------------------------------------------------------------
CREATE TABLE IF NOT EXISTS uploads (
    id              INT UNSIGNED NOT NULL AUTO_INCREMENT,
    patient_id      INT UNSIGNED NOT NULL,
    uploaded_by     INT UNSIGNED NOT NULL,   -- references users.id
    record_id       INT UNSIGNED,
    original_name   VARCHAR(255) NOT NULL,
    stored_name     VARCHAR(255) NOT NULL,   -- UUID-based filename on disk
    file_size       INT UNSIGNED,
    mime_type       VARCHAR(100),
    upload_date     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (patient_id)  REFERENCES patients(id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(id)    ON DELETE CASCADE,
    FOREIGN KEY (record_id)   REFERENCES medical_records(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ----------------------------------------------------------------
-- audit_logs  (security events and access logging)
-- ----------------------------------------------------------------
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

-- ----------------------------------------------------------------
-- Seed: default admin account
-- Password: Admin@1234  (Werkzeug pbkdf2:sha256 hash)
-- CHANGE THIS PASSWORD immediately after first login.
-- ----------------------------------------------------------------
INSERT IGNORE INTO users (username, password, role, full_name, email)
VALUES (
    'admin',
    'pbkdf2:sha256:600000$placeholder$changethishash',
    'admin',
    'System Administrator',
    'admin@securemed.local'
);
