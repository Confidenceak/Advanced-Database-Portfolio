-- =====================================================================
-- MIT 8103 Advanced Database Systems — Portfolio 1
-- Case study: CyberAce Tech Security Ltd (simulated global MSSP)
-- File:       import_real_data.sql — loads REAL public reference data
--
-- Sources:
--   1. CISA Known Exploited Vulnerabilities (KEV) catalog
--        data/kev/known_exploited_vulnerabilities.csv
--   2. MITRE ATT&CK Enterprise (STIX bundle converted to CSV by
--        data/scripts/prepare_mitre.py)
--        data/mitre/mitre_tactics.csv
--        data/mitre/mitre_techniques.csv
--        data/mitre/mitre_technique_tactics.csv
--
-- HOW TO RUN (pgAdmin):
--   Uses psql's \copy command, so it must run in the PSQL Tool,
--   NOT the Query Tool.
--   1. Select database cyberace_soc -> Tools -> PSQL Tool
--   2. Move psql into your repository folder (use forward slashes):
--        \cd 'C:/Users/YOUR-NAME/Documents/Advanced-Database-Portfolio'
--   3. Run this file:
--        \i portfolio-1-database-design/import_real_data.sql
--
-- Method (ETL — Extract, Transform, Load):
--   Extract   : \copy each CSV into a "staging" table where every column is TEXT
--   Transform : convert types, rename columns, split multi-value cells
--   Load      : INSERT into the real tables. ON CONFLICT makes the script
--               safe to re-run (existing rows are updated, not duplicated).
-- =====================================================================

\set ON_ERROR_STOP on
\echo '== Importing real reference data into cyberace_soc =='


-- ---------------------------------------------------------------------
-- 1. EXTRACT — staging tables (all TEXT, exactly like the source files)
-- ---------------------------------------------------------------------
DROP SCHEMA IF EXISTS staging CASCADE;
CREATE SCHEMA staging;

CREATE TABLE staging.kev_raw (
    cve_id                          TEXT,
    vendor_project                  TEXT,
    product                         TEXT,
    vulnerability_name              TEXT,
    date_added                      TEXT,
    short_description               TEXT,
    required_action                 TEXT,
    due_date                        TEXT,
    known_ransomware_campaign_use   TEXT,
    forensic_triage                 TEXT,
    notes                           TEXT,
    cwes                            TEXT
);

CREATE TABLE staging.mitre_tactics_raw (
    tactic_id  TEXT,
    name       TEXT,
    shortname  TEXT
);

CREATE TABLE staging.mitre_techniques_raw (
    technique_id         TEXT,
    name                 TEXT,
    is_subtechnique      TEXT,
    parent_technique_id  TEXT
);

CREATE TABLE staging.mitre_technique_tactics_raw (
    technique_id  TEXT,
    tactic_id     TEXT
);

\echo 'Loading CSV files...'
\copy staging.kev_raw                     FROM 'data/kev/known_exploited_vulnerabilities.csv' WITH (FORMAT csv, HEADER true, ENCODING 'UTF8')
\copy staging.mitre_tactics_raw           FROM 'data/mitre/mitre_tactics.csv'                 WITH (FORMAT csv, HEADER true, ENCODING 'UTF8')
\copy staging.mitre_techniques_raw        FROM 'data/mitre/mitre_techniques.csv'              WITH (FORMAT csv, HEADER true, ENCODING 'UTF8')
\copy staging.mitre_technique_tactics_raw FROM 'data/mitre/mitre_technique_tactics.csv'       WITH (FORMAT csv, HEADER true, ENCODING 'UTF8')


-- ---------------------------------------------------------------------
-- 2 & 3. TRANSFORM + LOAD — inside one transaction:
--        either everything loads, or nothing does.
-- ---------------------------------------------------------------------
BEGIN;

-- MITRE tactics
INSERT INTO mitre_tactic (tactic_id, name, shortname)
SELECT tactic_id, name, shortname
FROM   staging.mitre_tactics_raw
ON CONFLICT (tactic_id) DO UPDATE
    SET name = EXCLUDED.name, shortname = EXCLUDED.shortname;

-- MITRE techniques: parents first, so sub-techniques can reference them
INSERT INTO mitre_technique (technique_id, name, is_subtechnique, parent_technique_id)
SELECT technique_id, name, FALSE, NULL
FROM   staging.mitre_techniques_raw
WHERE  is_subtechnique = 'false'
ON CONFLICT (technique_id) DO UPDATE SET name = EXCLUDED.name;

INSERT INTO mitre_technique (technique_id, name, is_subtechnique, parent_technique_id)
SELECT technique_id, name, TRUE, parent_technique_id
FROM   staging.mitre_techniques_raw
WHERE  is_subtechnique = 'true'
ON CONFLICT (technique_id) DO UPDATE
    SET name = EXCLUDED.name, parent_technique_id = EXCLUDED.parent_technique_id;

-- MITRE technique <-> tactic links (many-to-many)
INSERT INTO technique_tactic (technique_id, tactic_id)
SELECT technique_id, tactic_id
FROM   staging.mitre_technique_tactics_raw
ON CONFLICT DO NOTHING;

-- CISA KEV vulnerabilities: rename columns, convert text to DATE and BOOLEAN
INSERT INTO vulnerability (cve_id, title, vendor_project, product, short_description,
                           required_action, date_added_to_kev, known_ransomware_use)
SELECT TRIM(cve_id),
       vulnerability_name,
       vendor_project,
       product,
       short_description,
       required_action,
       date_added::DATE,
       (known_ransomware_campaign_use = 'Known')
FROM   staging.kev_raw
ON CONFLICT (cve_id) DO UPDATE
    SET title                = EXCLUDED.title,
        vendor_project       = EXCLUDED.vendor_project,
        product              = EXCLUDED.product,
        short_description    = EXCLUDED.short_description,
        required_action      = EXCLUDED.required_action,
        date_added_to_kev    = EXCLUDED.date_added_to_kev,
        known_ransomware_use = EXCLUDED.known_ransomware_use;
        -- cvss_score is NOT overwritten: it comes from NVD, not KEV

-- CWEs: split "CWE-287, CWE-290, CWE-346" into one row per CWE (First Normal Form)
INSERT INTO vulnerability_cwe (cve_id, cwe_id)
SELECT DISTINCT TRIM(k.cve_id), TRIM(c.cwe)
FROM   staging.kev_raw AS k
CROSS  JOIN LATERAL regexp_split_to_table(k.cwes, ',') AS c(cwe)
WHERE  TRIM(c.cwe) <> ''
ON CONFLICT DO NOTHING;

COMMIT;


-- ---------------------------------------------------------------------
-- Clean up the staging area
-- ---------------------------------------------------------------------
DROP SCHEMA staging CASCADE;


-- ---------------------------------------------------------------------
-- Verification
-- ---------------------------------------------------------------------
\echo '== Rows loaded =='
SELECT 'mitre_tactic'      AS table_name, COUNT(*) AS row_count FROM mitre_tactic
UNION ALL SELECT 'mitre_technique (all)',           COUNT(*) FROM mitre_technique
UNION ALL SELECT '  of which sub-techniques',       COUNT(*) FROM mitre_technique WHERE is_subtechnique
UNION ALL SELECT 'technique_tactic',                COUNT(*) FROM technique_tactic
UNION ALL SELECT 'vulnerability (CISA KEV)',        COUNT(*) FROM vulnerability
UNION ALL SELECT '  used in ransomware campaigns',  COUNT(*) FROM vulnerability WHERE known_ransomware_use
UNION ALL SELECT 'vulnerability_cwe',               COUNT(*) FROM vulnerability_cwe;

\echo '== Example: one technique, many tactics (T1078 Valid Accounts) =='
SELECT t.technique_id, t.name AS technique, ta.tactic_id, ta.name AS tactic
FROM   mitre_technique  t
JOIN   technique_tactic tt ON tt.technique_id = t.technique_id
JOIN   mitre_tactic     ta ON ta.tactic_id    = tt.tactic_id
WHERE  t.technique_id = 'T1078'
ORDER  BY ta.tactic_id;

\echo '== Example: one KEV cell with several CWEs, now stored as separate rows =='
SELECT cve_id, cwe_id
FROM   vulnerability_cwe
WHERE  cve_id IN (SELECT cve_id FROM vulnerability_cwe GROUP BY cve_id HAVING COUNT(*) >= 3 LIMIT 1)
ORDER  BY cwe_id;
