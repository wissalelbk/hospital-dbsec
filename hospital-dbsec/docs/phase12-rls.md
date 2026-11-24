# Phase 12 (v2) — Row-Level Security in the database

Deepens the Phase 2 IDOR fix. File: `db/13_rls.sql`.

## Problem
In v1, a patient could only read their own records because the **application** injected `WHERE patient_id = :session`. If that check were ever missed (a new endpoint, a refactor), the base tables would leak other patients' rows (IDOR).

## Defense — enforce the filter in the database
MySQL/MariaDB have no native RLS and reject a session variable used directly in a view (`ERROR 1351`). We wrap the server-set variable `@app_patient_id` in a stored function and filter the view with it:

```sql
CREATE FUNCTION current_patient() RETURNS INT NOT DETERMINISTIC NO SQL
  RETURN CASE WHEN @app_patient_id REGEXP '^[0-9]+$'
              THEN CAST(@app_patient_id AS UNSIGNED) ELSE NULL END;

CREATE SQL SECURITY DEFINER VIEW v_patient_medical_records AS
  SELECT ... FROM medical_records WHERE patient_id = current_patient();
```

The patient DB role is granted `SELECT` on the **views only**, never on the base tables. The app runs `SET @app_patient_id = <session patient_id>` after login.

## Verified (4/4)
- `@app_patient_id = 1` → the view returns only patient 1's rows.
- `@app_patient_id = 5` → only patient 5's rows.
- **IDOR impossible**: even `SELECT … FROM v_patient_medical_records WHERE patient_id = 2` while acting as patient 1 returns **0 rows** — the view already filtered to patient 1.
- **Fail-closed**: if `@app_patient_id` is unset, the view returns **0 rows** (never all).

The regex guard also prevents the `Truncated incorrect DECIMAL` error and rejects any non-numeric injection of the variable.
