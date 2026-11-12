-- =====================================================================
-- MIT 8103 Advanced Database Systems — Portfolio 1
-- Case study: CyberAce Tech Security Ltd (simulated global MSSP)
-- System:     SOC Security Alert and Incident Management Database
-- DBMS:       PostgreSQL
-- Run in:     database "cyberace_soc"
-- Version:    2 — reshaped to hold REAL reference data:
--               * CISA Known Exploited Vulnerabilities (KEV) catalog
--               * MITRE ATT&CK Enterprise (tactics, techniques, sub-techniques)
-- Run order:  schema.sql -> import_real_data.sql -> sample_data.sql -> constraint_tests.sql
-- =====================================================================

-- Drop tables in reverse dependency order so the script can be re-run
DROP TABLE IF EXISTS audit_log           CASCADE;
DROP TABLE IF EXISTS remediation_task    CASCADE;
DROP TABLE IF EXISTS asset_vulnerability CASCADE;
DROP TABLE IF EXISTS alert_event         CASCADE;
DROP TABLE IF EXISTS vulnerability_cwe   CASCADE;
DROP TABLE IF EXISTS technique_tactic    CASCADE;
DROP TABLE IF EXISTS alert               CASCADE;
DROP TABLE IF EXISTS incident            CASCADE;
DROP TABLE IF EXISTS security_event      CASCADE;
DROP TABLE IF EXISTS asset               CASCADE;
DROP TABLE IF EXISTS vulnerability       CASCADE;
DROP TABLE IF EXISTS detection_rule      CASCADE;
DROP TABLE IF EXISTS mitre_technique     CASCADE;
DROP TABLE IF EXISTS mitre_tactic        CASCADE;
DROP TABLE IF EXISTS analyst             CASCADE;
DROP TABLE IF EXISTS client              CASCADE;


-- ---------------------------------------------------------------------
-- 1. CLIENT — organisations monitored by the SOC
-- ---------------------------------------------------------------------
CREATE TABLE client (
    client_id       SERIAL        PRIMARY KEY,
    name            VARCHAR(150)  NOT NULL UNIQUE,
    industry        VARCHAR(50)   NOT NULL,
    region          VARCHAR(20)   NOT NULL,
    country         VARCHAR(60)   NOT NULL,
    sla_tier        VARCHAR(10)   NOT NULL,
    contact_email   VARCHAR(150)  NOT NULL,
    onboarded_date  DATE          NOT NULL DEFAULT CURRENT_DATE,

    CONSTRAINT chk_client_region   CHECK (region   IN ('Africa', 'Europe', 'Middle East')),
    CONSTRAINT chk_client_sla_tier CHECK (sla_tier IN ('Gold', 'Silver', 'Bronze')),
    CONSTRAINT chk_client_email    CHECK (contact_email LIKE '%_@_%._%')
);


-- ---------------------------------------------------------------------
-- 2. ANALYST — SOC staff
-- ---------------------------------------------------------------------
CREATE TABLE analyst (
    analyst_id  SERIAL        PRIMARY KEY,
    full_name   VARCHAR(100)  NOT NULL,
    email       VARCHAR(150)  NOT NULL UNIQUE,
    tier        VARCHAR(2)    NOT NULL,
    shift       VARCHAR(5)    NOT NULL,

    CONSTRAINT chk_analyst_tier  CHECK (tier  IN ('L1', 'L2', 'L3')),
    CONSTRAINT chk_analyst_shift CHECK (shift IN ('Day', 'Night'))
);


-- ---------------------------------------------------------------------
-- 3. MITRE_TACTIC — the attacker's goal (REAL data: MITRE ATT&CK)
--    e.g. TA0006 Credential Access
-- ---------------------------------------------------------------------
CREATE TABLE mitre_tactic (
    tactic_id   VARCHAR(10)   PRIMARY KEY,
    name        VARCHAR(60)   NOT NULL UNIQUE,
    shortname   VARCHAR(60)   NOT NULL UNIQUE,

    CONSTRAINT chk_tactic_id CHECK (tactic_id ~ '^TA[0-9]{4}$')
);


-- ---------------------------------------------------------------------
-- 4. MITRE_TECHNIQUE — how the attacker achieves the goal (REAL data)
--    Sub-techniques (e.g. T1059.001 PowerShell) point to their parent
--    technique (T1059) through a self-referencing foreign key.
-- ---------------------------------------------------------------------
CREATE TABLE mitre_technique (
    technique_id         VARCHAR(12)   PRIMARY KEY,
    name                 VARCHAR(150)  NOT NULL,
    is_subtechnique      BOOLEAN       NOT NULL,
    parent_technique_id  VARCHAR(12),

    CONSTRAINT fk_technique_parent FOREIGN KEY (parent_technique_id)
        REFERENCES mitre_technique (technique_id) ON DELETE RESTRICT,
    CONSTRAINT chk_technique_id CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    -- a sub-technique must have a parent; a main technique must not
    CONSTRAINT chk_technique_parent CHECK (is_subtechnique = (parent_technique_id IS NOT NULL))
);


-- ---------------------------------------------------------------------
-- 5. TECHNIQUE_TACTIC — junction table (M:N)
--    One technique can serve several tactics,
--    e.g. T1078 Valid Accounts belongs to 4 tactics.
-- ---------------------------------------------------------------------
CREATE TABLE technique_tactic (
    technique_id  VARCHAR(12)  NOT NULL,
    tactic_id     VARCHAR(10)  NOT NULL,

    CONSTRAINT pk_technique_tactic PRIMARY KEY (technique_id, tactic_id),
    CONSTRAINT fk_tt_technique FOREIGN KEY (technique_id)
        REFERENCES mitre_technique (technique_id) ON DELETE CASCADE,
    CONSTRAINT fk_tt_tactic    FOREIGN KEY (tactic_id)
        REFERENCES mitre_tactic (tactic_id) ON DELETE CASCADE
);


-- ---------------------------------------------------------------------
-- 6. DETECTION_RULE — CyberAce's own rules that turn events into alerts
--    Each rule is mapped to a real MITRE technique (foreign key),
--    instead of storing the technique ID as free text (version 1).
-- ---------------------------------------------------------------------
CREATE TABLE detection_rule (
    rule_id           SERIAL        PRIMARY KEY,
    rule_name         VARCHAR(150)  NOT NULL UNIQUE,
    technique_id      VARCHAR(12),
    default_severity  VARCHAR(10)   NOT NULL,
    log_source        VARCHAR(30)   NOT NULL,

    CONSTRAINT fk_rule_technique FOREIGN KEY (technique_id)
        REFERENCES mitre_technique (technique_id) ON DELETE RESTRICT,
    CONSTRAINT chk_rule_severity CHECK (default_severity IN ('Low', 'Medium', 'High', 'Critical'))
);


-- ---------------------------------------------------------------------
-- 7. VULNERABILITY — known exploited CVEs (REAL data: CISA KEV catalog)
--    Columns kept from KEV:  cveID, vendorProject, product, vulnerabilityName,
--                            dateAdded, shortDescription, requiredAction,
--                            knownRansomwareCampaignUse
--    Columns skipped:        dueDate (US federal deadline), notes (links),
--                            forensicTriage (rarely used flag)
--    cwes -> moved to its own table (vulnerability_cwe) because one cell
--            can hold several values, which breaks First Normal Form.
--    cvss_score is not in KEV, so it is optional; it is filled from the
--    NIST NVD only for CVEs found on client assets.
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability (
    cve_id                VARCHAR(20)   PRIMARY KEY,
    title                 VARCHAR(200)  NOT NULL,
    vendor_project        VARCHAR(60)   NOT NULL,
    product               VARCHAR(200)  NOT NULL,
    short_description     TEXT,
    required_action       TEXT,
    date_added_to_kev     DATE          NOT NULL,
    known_ransomware_use  BOOLEAN       NOT NULL DEFAULT FALSE,
    cvss_score            NUMERIC(3,1),

    CONSTRAINT chk_vuln_cvss   CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    CONSTRAINT chk_vuln_cve_id CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$')
);


-- ---------------------------------------------------------------------
-- 8. VULNERABILITY_CWE — junction table (M:N): weakness types per CVE
--    e.g. a KEV cell "CWE-287, CWE-290, CWE-346" becomes three rows.
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability_cwe (
    cve_id  VARCHAR(20)  NOT NULL,
    cwe_id  VARCHAR(15)  NOT NULL,

    CONSTRAINT pk_vulnerability_cwe PRIMARY KEY (cve_id, cwe_id),
    CONSTRAINT fk_vc_cve FOREIGN KEY (cve_id)
        REFERENCES vulnerability (cve_id) ON DELETE CASCADE,
    CONSTRAINT chk_cwe_id CHECK (cwe_id ~ '^CWE-[0-9]+$')
);


-- ---------------------------------------------------------------------
-- 9. ASSET — devices/systems owned by a client
-- ---------------------------------------------------------------------
CREATE TABLE asset (
    asset_id          SERIAL        PRIMARY KEY,
    client_id         INTEGER       NOT NULL,
    hostname          VARCHAR(100)  NOT NULL,
    ip_address        INET          NOT NULL,
    asset_type        VARCHAR(30)   NOT NULL,
    operating_system  VARCHAR(50),
    criticality       VARCHAR(10)   NOT NULL,

    CONSTRAINT fk_asset_client FOREIGN KEY (client_id)
        REFERENCES client (client_id) ON DELETE RESTRICT,
    CONSTRAINT uq_asset_client_hostname UNIQUE (client_id, hostname),
    CONSTRAINT chk_asset_type CHECK (asset_type IN
        ('Server', 'Workstation', 'Firewall', 'Router', 'Cloud VM', 'Database')),
    CONSTRAINT chk_asset_criticality CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical'))
);


-- ---------------------------------------------------------------------
-- 10. SECURITY_EVENT — raw logs (high-volume table)
-- ---------------------------------------------------------------------
CREATE TABLE security_event (
    event_id          BIGSERIAL     PRIMARY KEY,
    asset_id          INTEGER       NOT NULL,
    event_time        TIMESTAMP     NOT NULL,
    event_type        VARCHAR(50)   NOT NULL,
    source_ip         INET,
    destination_ip    INET,
    destination_port  INTEGER,
    username          VARCHAR(100),
    raw_message       TEXT,

    CONSTRAINT fk_event_asset FOREIGN KEY (asset_id)
        REFERENCES asset (asset_id) ON DELETE RESTRICT,
    CONSTRAINT chk_event_port CHECK (destination_port BETWEEN 0 AND 65535)
);


-- ---------------------------------------------------------------------
-- 11. INCIDENT — confirmed security issue grouping alerts
-- ---------------------------------------------------------------------
CREATE TABLE incident (
    incident_id          SERIAL        PRIMARY KEY,
    client_id            INTEGER       NOT NULL,
    assigned_analyst_id  INTEGER,                    -- NULL = not yet claimed
    title                VARCHAR(200)  NOT NULL,
    severity             VARCHAR(10)   NOT NULL,
    status               VARCHAR(15)   NOT NULL DEFAULT 'New',
    opened_at            TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    closed_at            TIMESTAMP,

    CONSTRAINT fk_incident_client  FOREIGN KEY (client_id)
        REFERENCES client (client_id) ON DELETE RESTRICT,
    CONSTRAINT fk_incident_analyst FOREIGN KEY (assigned_analyst_id)
        REFERENCES analyst (analyst_id) ON DELETE SET NULL,
    CONSTRAINT chk_incident_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT chk_incident_status   CHECK (status IN ('New', 'In Progress', 'Contained', 'Closed')),
    CONSTRAINT chk_incident_dates    CHECK (closed_at IS NULL OR closed_at >= opened_at),
    -- A Closed incident must have a closing time; an open one must not
    CONSTRAINT chk_incident_closed   CHECK ((status = 'Closed') = (closed_at IS NOT NULL))
);


-- ---------------------------------------------------------------------
-- 12. ALERT — suspicious activity flagged by a rule
-- ---------------------------------------------------------------------
CREATE TABLE alert (
    alert_id      SERIAL        PRIMARY KEY,
    rule_id       INTEGER       NOT NULL,
    asset_id      INTEGER       NOT NULL,
    incident_id   INTEGER,                           -- NULL until linked to an incident
    triggered_at  TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity      VARCHAR(10)   NOT NULL,
    status        VARCHAR(20)   NOT NULL DEFAULT 'Open',

    CONSTRAINT fk_alert_rule     FOREIGN KEY (rule_id)
        REFERENCES detection_rule (rule_id) ON DELETE RESTRICT,
    CONSTRAINT fk_alert_asset    FOREIGN KEY (asset_id)
        REFERENCES asset (asset_id) ON DELETE RESTRICT,
    CONSTRAINT fk_alert_incident FOREIGN KEY (incident_id)
        REFERENCES incident (incident_id) ON DELETE SET NULL,
    CONSTRAINT chk_alert_severity CHECK (severity IN ('Low', 'Medium', 'High', 'Critical')),
    CONSTRAINT chk_alert_status   CHECK (status IN ('Open', 'Investigating', 'False Positive', 'Escalated'))
);


-- ---------------------------------------------------------------------
-- 13. ALERT_EVENT — junction table: which events triggered which alert (M:N)
-- ---------------------------------------------------------------------
CREATE TABLE alert_event (
    alert_id  INTEGER  NOT NULL,
    event_id  BIGINT   NOT NULL,

    CONSTRAINT pk_alert_event PRIMARY KEY (alert_id, event_id),
    CONSTRAINT fk_ae_alert FOREIGN KEY (alert_id)
        REFERENCES alert (alert_id) ON DELETE CASCADE,
    CONSTRAINT fk_ae_event FOREIGN KEY (event_id)
        REFERENCES security_event (event_id) ON DELETE CASCADE
);


-- ---------------------------------------------------------------------
-- 14. ASSET_VULNERABILITY — junction table: which CVEs affect which assets (M:N)
-- ---------------------------------------------------------------------
CREATE TABLE asset_vulnerability (
    asset_id      INTEGER       NOT NULL,
    cve_id        VARCHAR(20)   NOT NULL,
    detected_at   TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    patch_status  VARCHAR(15)   NOT NULL DEFAULT 'Unpatched',

    CONSTRAINT pk_asset_vulnerability PRIMARY KEY (asset_id, cve_id),
    CONSTRAINT fk_av_asset FOREIGN KEY (asset_id)
        REFERENCES asset (asset_id) ON DELETE CASCADE,
    CONSTRAINT fk_av_cve   FOREIGN KEY (cve_id)
        REFERENCES vulnerability (cve_id) ON DELETE RESTRICT,
    CONSTRAINT chk_av_patch_status CHECK (patch_status IN ('Unpatched', 'Patched', 'Accepted Risk'))
);


-- ---------------------------------------------------------------------
-- 15. REMEDIATION_TASK — actions to resolve an incident
-- ---------------------------------------------------------------------
CREATE TABLE remediation_task (
    task_id       SERIAL      PRIMARY KEY,
    incident_id   INTEGER     NOT NULL,
    analyst_id    INTEGER     NOT NULL,
    description   TEXT        NOT NULL,
    due_date      DATE        NOT NULL,
    status        VARCHAR(10) NOT NULL DEFAULT 'Pending',
    completed_at  TIMESTAMP,

    CONSTRAINT fk_task_incident FOREIGN KEY (incident_id)
        REFERENCES incident (incident_id) ON DELETE CASCADE,
    CONSTRAINT fk_task_analyst  FOREIGN KEY (analyst_id)
        REFERENCES analyst (analyst_id) ON DELETE RESTRICT,
    CONSTRAINT chk_task_status  CHECK (status IN ('Pending', 'Done')),
    CONSTRAINT chk_task_done    CHECK ((status = 'Done') = (completed_at IS NOT NULL))
);


-- ---------------------------------------------------------------------
-- 16. AUDIT_LOG — record of every analyst action
-- ---------------------------------------------------------------------
CREATE TABLE audit_log (
    log_id       BIGSERIAL    PRIMARY KEY,
    analyst_id   INTEGER      NOT NULL,
    action       VARCHAR(50)  NOT NULL,
    entity_type  VARCHAR(30)  NOT NULL,
    entity_id    BIGINT       NOT NULL,
    logged_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_audit_analyst FOREIGN KEY (analyst_id)
        REFERENCES analyst (analyst_id) ON DELETE RESTRICT
);


-- ---------------------------------------------------------------------
-- Verification: list every table and how many columns it has
-- ---------------------------------------------------------------------
SELECT table_name,
       COUNT(*) AS column_count
FROM   information_schema.columns
WHERE  table_schema = 'public'
GROUP  BY table_name
ORDER  BY table_name;
