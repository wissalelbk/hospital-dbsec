-- =====================================================================
--  Hospital Patient Records System — SCHEMA (BASELINE / "BEFORE")
--  Course: Database Security — Dr. A. O. Harazeem — UIR ESIN ING5
--
--  ⚠  BASELINE STATE (deliberately insecure for Phase 4 "attaque vierge"):
--     - sensitive columns (national_id, insurance_policy_no) stored in CLEARTEXT
--     - passwords stored in CLEARTEXT (migrated to Argon2id in db/05_secure_auth.sql)
--     - no audit objects (added in db/07_audit.sql)
--  The secure migrations (db/04..db/09) transform this into the hardened state.
--  Engine: MySQL 8.4 LTS
-- =====================================================================

DROP DATABASE IF EXISTS hospital;
CREATE DATABASE hospital CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
USE hospital;

-- ---------------------------------------------------------------------
-- Reference: roles (application-level RBAC categories)
-- ---------------------------------------------------------------------
CREATE TABLE roles (
    role_id      INT AUTO_INCREMENT PRIMARY KEY,
    role_name    VARCHAR(50)  NOT NULL UNIQUE,
    description  VARCHAR(255) NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Staff (doctors, nurses, receptionists, accountants, administrators)
-- ---------------------------------------------------------------------
CREATE TABLE staff (
    staff_id             INT AUTO_INCREMENT PRIMARY KEY,
    full_name            VARCHAR(120) NOT NULL,
    department           VARCHAR(80)  NULL,
    professional_license VARCHAR(60)  NULL,          -- moderately sensitive
    phone                VARCHAR(30)  NULL,
    hired_at             DATE         NULL
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Patients  (CONTAINS SENSITIVE PII + national identification)
--   national_id: BASELINE = cleartext VARCHAR  → migrated to VARBINARY (AES) in Phase 6
-- ---------------------------------------------------------------------
CREATE TABLE patients (
    patient_id        INT AUTO_INCREMENT PRIMARY KEY,
    national_id       VARCHAR(30)  NOT NULL,          -- ⚠ SENSITIVE, cleartext in baseline
    first_name        VARCHAR(80)  NOT NULL,
    last_name         VARCHAR(80)  NOT NULL,
    date_of_birth     DATE         NULL,
    gender            ENUM('M','F','Other') NULL,
    phone             VARCHAR(30)  NULL,
    address           VARCHAR(255) NULL,
    blood_type        VARCHAR(5)   NULL,
    emergency_contact VARCHAR(120) NULL,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_patient_national (national_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Application users (authentication accounts)
--   password_hash: BASELINE = cleartext  → Argon2id PHC string in Phase 3
-- ---------------------------------------------------------------------
CREATE TABLE app_users (
    user_id             INT AUTO_INCREMENT PRIMARY KEY,
    username            VARCHAR(64)  NOT NULL UNIQUE,
    password_hash       VARCHAR(255) NOT NULL,        -- ⚠ cleartext in baseline
    role_id             INT          NOT NULL,
    staff_id            INT          NULL,            -- set for staff accounts
    patient_id          INT          NULL,            -- set for patient-portal accounts
    is_active           TINYINT(1)   NOT NULL DEFAULT 1,
    failed_attempts     INT          NOT NULL DEFAULT 0,   -- used by lockout logic (Phase 3)
    locked_until        DATETIME     NULL,
    last_login_at       DATETIME     NULL,
    password_changed_at DATETIME     NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user_role    FOREIGN KEY (role_id)    REFERENCES roles(role_id),
    CONSTRAINT fk_user_staff   FOREIGN KEY (staff_id)   REFERENCES staff(staff_id),
    CONSTRAINT fk_user_patient FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Medical records  (SENSITIVE: diagnosis + clinical notes)
-- ---------------------------------------------------------------------
CREATE TABLE medical_records (
    record_id        INT AUTO_INCREMENT PRIMARY KEY,
    patient_id       INT NOT NULL,
    doctor_staff_id  INT NOT NULL,
    visit_date       DATETIME NOT NULL,
    diagnosis        VARCHAR(255) NULL,               -- ⚠ SENSITIVE (medical)
    treatment        TEXT         NULL,
    clinical_notes   TEXT         NULL,               -- ⚠ SENSITIVE (medical)
    created_at       TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_mr_patient FOREIGN KEY (patient_id)      REFERENCES patients(patient_id),
    CONSTRAINT fk_mr_doctor  FOREIGN KEY (doctor_staff_id) REFERENCES staff(staff_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Prescriptions
-- ---------------------------------------------------------------------
CREATE TABLE prescriptions (
    prescription_id INT AUTO_INCREMENT PRIMARY KEY,
    record_id       INT NOT NULL,
    medication      VARCHAR(120) NOT NULL,
    dosage          VARCHAR(80)  NULL,
    instructions    VARCHAR(255) NULL,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_rx_record FOREIGN KEY (record_id) REFERENCES medical_records(record_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Lab results  (SENSITIVE: result values)
-- ---------------------------------------------------------------------
CREATE TABLE lab_results (
    result_id          INT AUTO_INCREMENT PRIMARY KEY,
    patient_id         INT NOT NULL,
    ordered_by_staff_id INT NOT NULL,
    test_type          VARCHAR(100) NOT NULL,
    result_value       VARCHAR(255) NULL,             -- ⚠ SENSITIVE (medical)
    result_unit        VARCHAR(30)  NULL,
    reference_range    VARCHAR(60)  NULL,
    result_date        DATETIME NULL,
    CONSTRAINT fk_lab_patient FOREIGN KEY (patient_id)          REFERENCES patients(patient_id),
    CONSTRAINT fk_lab_staff   FOREIGN KEY (ordered_by_staff_id) REFERENCES staff(staff_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Appointments
-- ---------------------------------------------------------------------
CREATE TABLE appointments (
    appointment_id  INT AUTO_INCREMENT PRIMARY KEY,
    patient_id      INT NOT NULL,
    doctor_staff_id INT NOT NULL,
    scheduled_at    DATETIME NOT NULL,
    status          ENUM('scheduled','completed','cancelled','no_show') DEFAULT 'scheduled',
    reason          VARCHAR(255) NULL,
    CONSTRAINT fk_ap_patient FOREIGN KEY (patient_id)      REFERENCES patients(patient_id),
    CONSTRAINT fk_ap_doctor  FOREIGN KEY (doctor_staff_id) REFERENCES staff(staff_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Billing  (SENSITIVE: financial + insurance policy number)
--   insurance_policy_no: BASELINE = cleartext → VARBINARY (AES) in Phase 6
-- ---------------------------------------------------------------------
CREATE TABLE billing (
    invoice_id          INT AUTO_INCREMENT PRIMARY KEY,
    patient_id          INT NOT NULL,
    amount              DECIMAL(10,2) NOT NULL,
    insurance_provider  VARCHAR(120) NULL,
    insurance_policy_no VARCHAR(60)  NULL,            -- ⚠ SENSITIVE, cleartext in baseline
    status              ENUM('unpaid','paid','partial','void') DEFAULT 'unpaid',
    issued_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_by_staff_id INT NULL,
    CONSTRAINT fk_bill_patient FOREIGN KEY (patient_id)          REFERENCES patients(patient_id),
    CONSTRAINT fk_bill_staff   FOREIGN KEY (created_by_staff_id) REFERENCES staff(staff_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Seed the role catalogue (users come from db/02_seed.sql)
-- ---------------------------------------------------------------------
INSERT INTO roles (role_name, description) VALUES
 ('DBA',          'Database administrator — full administrative control'),
 ('Doctor',       'Physician — full clinical access to own patients'),
 ('Nurse',        'Nursing staff — read clinical data, update vitals/notes'),
 ('Receptionist', 'Front desk — demographics and appointments only'),
 ('Accountant',   'Billing staff — financial/billing data only'),
 ('Patient',      'Patient portal — own records only'),
 ('AppService',   'Application service account — least privilege for the web app');

-- End of baseline schema.
