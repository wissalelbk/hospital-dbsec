-- =====================================================================
--  Hospital Patient Records System — SEED DATA (BASELINE)
--  Passwords are CLEARTEXT here on purpose (baseline). Phase 3 replaces
--  this table's password_hash values with Argon2id PHC strings.
--  Load order: 01_schema.sql → 02_seed.sql
-- =====================================================================
USE hospital;

-- ---------- Staff ----------
INSERT INTO staff (full_name, department, professional_license, phone, hired_at) VALUES
 ('Dr. Youssef Amrani',   'Cardiology',  'MD-RAB-10231', '0600-100-201', '2019-03-01'),
 ('Dr. Salma Bennani',    'Oncology',    'MD-RAB-10488', '0600-100-202', '2020-09-15'),
 ('Nurse Hajar El Idrissi','Cardiology', 'RN-RAB-22150', '0600-100-203', '2021-01-10'),
 ('Nurse Omar Fassi',     'General',     'RN-RAB-22311', '0600-100-204', '2022-06-20'),
 ('Fatima Zahra (Reception)','Front Desk', NULL,          '0600-100-205', '2021-11-02'),
 ('Karim Tahiri (Billing)','Finance',    NULL,            '0600-100-206', '2020-02-17'),
 ('Admin Root',           'IT',          NULL,            '0600-100-207', '2018-01-01');

-- ---------- Patients (national_id cleartext in baseline) ----------
INSERT INTO patients (national_id, first_name, last_name, date_of_birth, gender, phone, address, blood_type, emergency_contact) VALUES
 ('AA112233', 'Mehdi',  'Alaoui',   '1985-04-12', 'M', '0611-000-001', '12 Rue Hassan II, Rabat',   'O+',  'Nadia Alaoui 0611-000-010'),
 ('BB223344', 'Imane',  'Chraibi',  '1992-11-30', 'F', '0611-000-002', '8 Av. Mohammed V, Salé',    'A-',  'Rachid Chraibi 0611-000-011'),
 ('CC334455', 'Yassine','Berrada',  '1978-07-05', 'M', '0611-000-003', '45 Rue de Fès, Rabat',      'B+',  'Sara Berrada 0611-000-012'),
 ('DD445566', 'Laila',  'Haddad',   '2001-02-19', 'F', '0611-000-004', '3 Rue Oujda, Témara',       'AB+', 'Nabil Haddad 0611-000-013'),
 ('EE556677', 'Oussama', 'Naciri',  '1965-12-01', 'M', '0611-000-005', '77 Bd Zerktouni, Rabat',    'O-',  'Hanane Naciri 0611-000-014'),
 ('FF667788', 'Khadija','Benjelloun','1989-08-23','F', '0611-000-006', '21 Rue Agadir, Salé',       'A+',  'Tarik Benjelloun 0611-000-015'),
 ('GG778899', 'Hamza',  'Sabri',    '1995-05-14', 'M', '0611-000-007', '9 Rue Tanger, Rabat',       'B-',  'Leila Sabri 0611-000-016'),
 ('HH889900', 'Sanaa',  'Ouazzani', '1970-03-28', 'F', '0611-000-008', '55 Av. An-Nasr, Rabat',     'O+',  'Said Ouazzani 0611-000-017');

-- ---------- Application users (CLEARTEXT passwords — baseline) ----------
-- role_id: 1 DBA, 2 Doctor, 3 Nurse, 4 Receptionist, 5 Accountant, 6 Patient, 7 AppService
INSERT INTO app_users (username, password_hash, role_id, staff_id, patient_id) VALUES
 ('admin',       'Admin@123',       1, 7,  NULL),
 ('dr.amrani',   'Doctor@123',      2, 1,  NULL),
 ('dr.bennani',  'Doctor@456',      2, 2,  NULL),
 ('nurse.hajar', 'Nurse@123',       3, 3,  NULL),
 ('nurse.omar',  'Nurse@456',       3, 4,  NULL),
 ('reception',   'Reception@123',   4, 5,  NULL),
 ('billing',     'Billing@123',     5, 6,  NULL),
 ('p.alaoui',    'Patient@123',     6, NULL, 1),
 ('p.chraibi',   'Patient@456',     6, NULL, 2);

-- ---------- Medical records (SENSITIVE) ----------
INSERT INTO medical_records (patient_id, doctor_staff_id, visit_date, diagnosis, treatment, clinical_notes) VALUES
 (1, 1, '2026-10-01 09:30:00', 'Hypertension stage 1', 'Lifestyle changes + amlodipine', 'BP 148/95, review in 4 weeks'),
 (2, 2, '2026-10-03 11:00:00', 'Breast carcinoma (suspected)', 'Biopsy ordered', 'Family history positive; urgent oncology follow-up'),
 (3, 1, '2026-10-05 14:15:00', 'Atrial fibrillation', 'Anticoagulation (apixaban)', 'Palpitations, ECG confirms AF'),
 (5, 1, '2026-10-06 08:45:00', 'Type 2 diabetes + CKD', 'Metformin, nephrology referral', 'eGFR declining, monitor closely'),
 (1, 1, '2026-10-20 10:00:00', 'Hypertension — follow-up', 'Continue amlodipine', 'BP improved 132/84');

-- ---------- Prescriptions ----------
INSERT INTO prescriptions (record_id, medication, dosage, instructions) VALUES
 (1, 'Amlodipine', '5 mg', 'Once daily, morning'),
 (3, 'Apixaban',   '5 mg', 'Twice daily'),
 (4, 'Metformin',  '850 mg', 'Twice daily with meals'),
 (5, 'Amlodipine', '5 mg', 'Once daily, continue');

-- ---------- Lab results (SENSITIVE) ----------
INSERT INTO lab_results (patient_id, ordered_by_staff_id, test_type, result_value, result_unit, reference_range, result_date) VALUES
 (2, 2, 'Biopsy (histopathology)', 'Malignant cells present', '', 'Negative', '2026-10-08 16:00:00'),
 (5, 1, 'eGFR',  '42', 'mL/min/1.73m2', '>60', '2026-10-06 09:30:00'),
 (5, 1, 'HbA1c', '8.9', '%', '<5.7', '2026-10-06 09:30:00'),
 (3, 1, 'INR',   '2.4', '', '2.0-3.0', '2026-10-10 10:00:00');

-- ---------- Appointments ----------
INSERT INTO appointments (patient_id, doctor_staff_id, scheduled_at, status, reason) VALUES
 (1, 1, '2026-11-17 09:30:00', 'scheduled', 'BP follow-up'),
 (2, 2, '2026-11-10 11:00:00', 'scheduled', 'Oncology consult'),
 (4, 1, '2026-11-12 15:00:00', 'scheduled', 'General check-up'),
 (3, 1, '2026-10-10 10:00:00', 'completed', 'AF review');

-- ---------- Billing (SENSITIVE: insurance policy number cleartext in baseline) ----------
INSERT INTO billing (patient_id, amount, insurance_provider, insurance_policy_no, status, created_by_staff_id) VALUES
 (1, 450.00, 'CNSS',  'CNSS-PL-889001', 'paid',    6),
 (2, 1200.00,'CNOPS', 'CNOPS-PL-445213','unpaid',  6),
 (3, 300.00, 'RMA',   'RMA-PL-220144',  'partial', 6),
 (5, 980.00, 'CNSS',  'CNSS-PL-889077', 'unpaid',  6);

-- End of seed data.
