-- =====================================================================
-- MIT 8103 Advanced Database Systems — Portfolio 1
-- Case study: CyberAce Tech Security Ltd (simulated global MSSP)
-- System:     SOC Security Alert and Incident Management Database
-- DBMS:       PostgreSQL
-- Run in:     database "cyberace_soc"
-- =====================================================================

-- Drop tables in reverse dependency order so the script can be re-run
DROP TABLE IF EXISTS audit_log           CASCADE;
DROP TABLE IF EXISTS remediation_task    CASCADE;
DROP TABLE IF EXISTS asset_vulnerability CASCADE;
DROP TABLE IF EXISTS alert_event         CASCADE;
DROP TABLE IF EXISTS alert               CASCADE;
DROP TABLE IF EXISTS incident            CASCADE;
DROP TABLE IF EXISTS security_event      CASCADE;
DROP TABLE IF EXISTS asset               CASCADE;
DROP TABLE IF EXISTS vulnerability       CASCADE;
DROP TABLE IF EXISTS detection_rule      CASCADE;
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
-- 3. DETECTION_RULE — logic that turns events into alerts
-- ---------------------------------------------------------------------
CREATE TABLE detection_rule (
    rule_id           SERIAL        PRIMARY KEY,
    rule_name         VARCHAR(150)  NOT NULL UNIQUE,
    mitre_technique   VARCHAR(20),
    default_severity  VARCHAR(10)   NOT NULL,
    log_source        VARCHAR(30)   NOT NULL,

    CONSTRAINT chk_rule_severity CHECK (default_severity IN ('Low', 'Medium', 'High', 'Critical'))
);


-- ---------------------------------------------------------------------
-- 4. VULNERABILITY — known CVEs
-- ---------------------------------------------------------------------
CREATE TABLE vulnerability (
    cve_id          VARCHAR(20)   PRIMARY KEY,
    title           VARCHAR(200)  NOT NULL,
    cvss_score      NUMERIC(3,1)  NOT NULL,
    published_date  DATE,

    CONSTRAINT chk_vuln_cvss   CHECK (cvss_score BETWEEN 0.0 AND 10.0),
    CONSTRAINT chk_vuln_cve_id CHECK (cve_id LIKE 'CVE-____-%')
);


-- ---------------------------------------------------------------------
-- 5. ASSET — devices/systems owned by a client
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
-- 6. SECURITY_EVENT — raw logs (high-volume table)
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
-- 7. INCIDENT — confirmed security issue grouping alerts
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
-- 8. ALERT — suspicious activity flagged by a rule
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
-- 9. ALERT_EVENT — junction table: which events triggered which alert (M:N)
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
-- 10. ASSET_VULNERABILITY — junction table: which CVEs affect which assets (M:N)
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
-- 11. REMEDIATION_TASK — actions to resolve an incident
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
-- 12. AUDIT_LOG — record of every analyst action
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
