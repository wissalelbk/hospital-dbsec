# Phase 10 — Security Incident Investigation

Hospital Patient Records System — UIR ESIN ING5, Database Security (Dr. Harazeem)

> Simulated incident investigated using the audit evidence from Phase 7. The exercise shows the collected data can reconstruct *what happened*.

---

## 1. Scenario

Alert: several unauthorized attempts to access sensitive information, and a privileged account performing unusual operations, overnight. The Database Security Team investigates using `audit_log`.

## 2. Investigation method

Queries run against `audit_log` (full output captured during testing):

1. **Failed-login clusters** → brute-force detection.
2. **First successful login** from the suspect source.
3. **Full action trail** for the source IP, ordered → the timeline.
4. **Privileged/integrity actions** in the window.

## 3. Findings — the seven questions

| Question | Finding (from evidence) |
|----------|-------------------------|
| **What happened?** | Brute-force against `admin`, then a successful login, bulk reading of medical records, an account change, and a billing modification |
| **When?** | 2026-11-05, 02:14:03 → 02:19:02 (overnight, outside working hours) |
| **Which account(s)?** | Target `admin`; all activity from source IP **192.168.56.30** (the kali-vm / attacker host — not the app server 192.168.56.20) |
| **Which resources affected?** | `patients` (search), `medical_records` #1,2,3,5 (read), `app_users` #4 (account change), `billing` #2 (modified) |
| **Which controls failed?** | In the *baseline*: no lockout (brute force succeeded), weak password, direct DB reachability from a workstation |
| **What evidence?** | `audit_log` rows: 5× `LOGIN_FAIL` 02:14:03–02:14:36, `LOGIN_SUCCESS` 02:15:58, 4× `VIEW_MEDICAL_RECORD`, `ACCOUNT_CHANGE` 02:18:20, `UPDATE billing` 02:19:02 — all from 192.168.56.30 |
| **Corrective actions?** | See §5 |

## 4. Incident timeline (reconstructed)

| Time (2026-11-05) | Actor | Action | Resource |
|-------------------|-------|--------|----------|
| 02:14:03–02:14:36 | admin ← 192.168.56.30 | 5 × **LOGIN_FAIL** | — |
| 02:15:58 | admin ← 192.168.56.30 | **LOGIN_SUCCESS** | — |
| 02:16:40 | admin | PATIENT_SEARCH | patients |
| 02:16:52–02:17:12 | admin | 4 × VIEW_MEDICAL_RECORD | medical_records #1,2,3,5 |
| 02:18:20 | admin | **ACCOUNT_CHANGE** | app_users #4 |
| 02:19:02 | admin | **UPDATE** | billing #2 |

The source IP (192.168.56.30) is decisive: legitimate `admin` activity comes from the app server (192.168.56.20); this session came straight from a workstation, confirming the compromise.

## 5. Corrective actions (link to the hardening already implemented)

| Failure observed | Control that prevents recurrence | Phase |
|------------------|----------------------------------|-------|
| Brute force succeeded | Account lockout after 5 failures (tested) + Argon2id | 3 |
| Weak/guessable password | `validate_password` STRONG policy | 9 |
| DB reachable from a workstation | `bind-address` + firewall (only app-vm → 3306) | 9 |
| Privileged action unnoticed | Real-time alerting on `v_failed_logins` / `ACCOUNT_CHANGE` | 7/10 |
| Billing tampering | Least privilege + audit trail for attribution/rollback | 2/7/8 |

## 6. Lessons

The investigation was only possible **because the audit layer existed** — recall that in the baseline (attack A4) there were no logs at all, and this exact incident would have been invisible. Auditing (Phase 7) plus the lockout, password policy and network segmentation (Phases 3, 9) together both **prevent** and **detect** the incident, closing the loop of the project's security lifecycle.
