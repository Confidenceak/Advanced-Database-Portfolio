-- =====================================================================
-- MIT 8103 Advanced Database Systems — Portfolio 1
-- File:      constraint_tests.sql — proves the constraints enforce the business rules
-- Run AFTER: schema.sql, import_real_data.sql and sample_data.sql
--
-- Each test deliberately tries to break a rule. A PASS means the database
-- REJECTED the bad data. Results appear in pgAdmin's "Messages" tab.
-- =====================================================================

-- TEST 1: CVSS score must be between 0.0 and 10.0  (CHECK)
DO $$ BEGIN
    INSERT INTO vulnerability (cve_id, title, vendor_project, product, date_added_to_kev, cvss_score)
    VALUES ('CVE-2026-99999', 'Fake vuln', 'Test', 'Test', '2026-11-11', 15.0);
    RAISE NOTICE 'TEST 1 FAILED: CVSS score 15.0 was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 1 PASSED (CVSS > 10 rejected): %', SQLERRM;
END $$;

-- TEST 2: severity must be Low / Medium / High / Critical  (CHECK)
DO $$ BEGIN
    INSERT INTO incident (client_id, title, severity) VALUES (1, 'Bad severity test', 'Extreme');
    RAISE NOTICE 'TEST 2 FAILED: severity "Extreme" was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 2 PASSED (invalid severity rejected): %', SQLERRM;
END $$;

-- TEST 3: an incident cannot close before it opened  (CHECK)
DO $$ BEGIN
    INSERT INTO incident (client_id, title, severity, status, opened_at, closed_at)
    VALUES (1, 'Time travel test', 'Low', 'Closed', '2026-11-10 10:00', '2026-11-09 10:00');
    RAISE NOTICE 'TEST 3 FAILED: closed_at before opened_at was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 3 PASSED (closed before opened rejected): %', SQLERRM;
END $$;

-- TEST 4: a Closed incident must have a closed_at time  (CHECK)
DO $$ BEGIN
    INSERT INTO incident (client_id, title, severity, status) VALUES (1, 'Closed without time', 'Low', 'Closed');
    RAISE NOTICE 'TEST 4 FAILED: Closed incident with no closed_at was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 4 PASSED (Closed status without closed_at rejected): %', SQLERRM;
END $$;

-- TEST 5: a task marked Done must have a completed_at time  (CHECK)
DO $$ BEGIN
    INSERT INTO remediation_task (incident_id, analyst_id, description, due_date, status)
    VALUES (2, 5, 'Done but no time', '2026-11-20', 'Done');
    RAISE NOTICE 'TEST 5 FAILED: Done task with no completed_at was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 5 PASSED (Done task without completed_at rejected): %', SQLERRM;
END $$;

-- TEST 6: an asset must belong to a client that exists  (FOREIGN KEY)
DO $$ BEGIN
    INSERT INTO asset (client_id, hostname, ip_address, asset_type, criticality)
    VALUES (999, 'ghost-host', '10.99.0.1', 'Server', 'Low');
    RAISE NOTICE 'TEST 6 FAILED: asset for non-existent client 999 was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 6 PASSED (orphan asset rejected): %', SQLERRM;
END $$;

-- TEST 7: a client with assets cannot be deleted  (FOREIGN KEY ... ON DELETE RESTRICT)
DO $$ BEGIN
    DELETE FROM client WHERE client_id = 1;
    RAISE NOTICE 'TEST 7 FAILED: client with assets was deleted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 7 PASSED (delete of client with assets blocked): %', SQLERRM;
END $$;

-- TEST 8: analyst emails must be unique  (UNIQUE)
DO $$ BEGIN
    INSERT INTO analyst (full_name, email, tier, shift)
    VALUES ('Impostor', 'a.okafor@cyberacetech.example', 'L1', 'Day');
    RAISE NOTICE 'TEST 8 FAILED: duplicate analyst email was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 8 PASSED (duplicate email rejected): %', SQLERRM;
END $$;

-- TEST 9: hostname must be unique within the same client  (composite UNIQUE)
DO $$ BEGIN
    INSERT INTO asset (client_id, hostname, ip_address, asset_type, criticality)
    VALUES (1, 'zmb-core-db01', '10.10.1.99', 'Database', 'High');
    RAISE NOTICE 'TEST 9 FAILED: duplicate hostname for the same client was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 9 PASSED (duplicate hostname within client rejected): %', SQLERRM;
END $$;

-- TEST 10: IP addresses must be valid  (INET data type)
DO $$ BEGIN
    INSERT INTO asset (client_id, hostname, ip_address, asset_type, criticality)
    VALUES (1, 'bad-ip-host', '999.10.1.1', 'Server', 'Low');
    RAISE NOTICE 'TEST 10 FAILED: invalid IP 999.10.1.1 was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 10 PASSED (invalid IP address rejected): %', SQLERRM;
END $$;

-- TEST 11: port numbers must be 0-65535  (CHECK)
DO $$ BEGIN
    INSERT INTO security_event (asset_id, event_time, event_type, destination_port)
    VALUES (1, '2026-11-10 12:00', 'test', 70000);
    RAISE NOTICE 'TEST 11 FAILED: port 70000 was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 11 PASSED (port > 65535 rejected): %', SQLERRM;
END $$;

-- TEST 12: required fields cannot be empty  (NOT NULL)
DO $$ BEGIN
    INSERT INTO asset (client_id, hostname, ip_address, asset_type, criticality)
    VALUES (1, NULL, '10.10.9.9', 'Server', 'Low');
    RAISE NOTICE 'TEST 12 FAILED: asset with no hostname was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 12 PASSED (missing hostname rejected): %', SQLERRM;
END $$;


-- =====================================================================
-- TEST 13: ON DELETE CASCADE and ON DELETE SET NULL
-- Deleting incident 3 should delete its remediation tasks (CASCADE)
-- and unlink its alerts without deleting them (SET NULL).
-- The block then raises an exception on purpose, which UNDOES the
-- delete, so no sample data is actually lost.
-- =====================================================================
DO $$
DECLARE
    tasks_before INT;  links_before INT;
    tasks_after  INT;  links_after  INT;  alerts_after INT;
BEGIN
    SELECT COUNT(*) INTO tasks_before FROM remediation_task WHERE incident_id = 3;
    SELECT COUNT(*) INTO links_before FROM alert WHERE incident_id = 3;

    BEGIN
        DELETE FROM incident WHERE incident_id = 3;

        SELECT COUNT(*) INTO tasks_after  FROM remediation_task WHERE incident_id = 3;
        SELECT COUNT(*) INTO links_after  FROM alert WHERE incident_id = 3;
        SELECT COUNT(*) INTO alerts_after FROM alert WHERE alert_id IN (4, 5);

        RAISE NOTICE 'TEST 13 BEFORE delete: % tasks, % alerts linked to incident 3', tasks_before, links_before;
        RAISE NOTICE 'TEST 13 AFTER delete:  % tasks (CASCADE), % alerts linked (SET NULL), % of alerts 4-5 still exist',
                     tasks_after, links_after, alerts_after;

        IF tasks_after = 0 AND links_after = 0 AND alerts_after = 2 THEN
            RAISE NOTICE 'TEST 13 PASSED (tasks cascaded, alerts kept but unlinked)';
        ELSE
            RAISE NOTICE 'TEST 13 FAILED';
        END IF;

        RAISE EXCEPTION 'undo';           -- forces the delete to be rolled back
    EXCEPTION WHEN raise_exception THEN
        RAISE NOTICE 'TEST 13 cleanup: delete rolled back, incident 3 restored';
    END;
END $$;

-- Confirm incident 3 and its tasks are back
SELECT incident_id, title, status,
       (SELECT COUNT(*) FROM remediation_task t WHERE t.incident_id = i.incident_id) AS tasks
FROM incident i
WHERE incident_id = 3;


-- =====================================================================
-- TESTS 14-19: rules on the REAL reference data (MITRE ATT&CK, CISA KEV)
-- =====================================================================

-- TEST 14: a sub-technique must have a parent technique  (CHECK)
DO $$ BEGIN
    INSERT INTO mitre_technique (technique_id, name, is_subtechnique, parent_technique_id)
    VALUES ('T1059.999', 'Orphan sub-technique', TRUE, NULL);
    RAISE NOTICE 'TEST 14 FAILED: sub-technique without a parent was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 14 PASSED (sub-technique without parent rejected): %', SQLERRM;
END $$;

-- TEST 15: technique IDs must follow the ATT&CK format Txxxx or Txxxx.xxx  (CHECK)
DO $$ BEGIN
    INSERT INTO mitre_technique (technique_id, name, is_subtechnique) VALUES ('X999', 'Bad ID', FALSE);
    RAISE NOTICE 'TEST 15 FAILED: invalid technique ID was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 15 PASSED (invalid technique ID format rejected): %', SQLERRM;
END $$;

-- TEST 16: a detection rule must map to a technique that exists  (FOREIGN KEY)
DO $$ BEGIN
    INSERT INTO detection_rule (rule_name, technique_id, default_severity, log_source)
    VALUES ('Rule with fake technique', 'T9999', 'Low', 'IDS');
    RAISE NOTICE 'TEST 16 FAILED: rule with non-existent technique was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 16 PASSED (unknown MITRE technique rejected): %', SQLERRM;
END $$;

-- TEST 17: CWE IDs must follow the format CWE-<number>  (CHECK)
DO $$ BEGIN
    INSERT INTO vulnerability_cwe (cve_id, cwe_id) VALUES ('CVE-2021-44228', 'CWE-abc');
    RAISE NOTICE 'TEST 17 FAILED: invalid CWE ID was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 17 PASSED (invalid CWE format rejected): %', SQLERRM;
END $$;

-- TEST 18: the same CWE cannot be linked to the same CVE twice  (composite PRIMARY KEY)
DO $$
DECLARE existing_cve VARCHAR; existing_cwe VARCHAR;
BEGIN
    SELECT cve_id, cwe_id INTO existing_cve, existing_cwe FROM vulnerability_cwe LIMIT 1;
    INSERT INTO vulnerability_cwe (cve_id, cwe_id) VALUES (existing_cve, existing_cwe);
    RAISE NOTICE 'TEST 18 FAILED: duplicate CVE-CWE link was accepted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 18 PASSED (duplicate CVE-CWE link rejected): %', SQLERRM;
END $$;

-- TEST 19: a MITRE technique used by a detection rule cannot be deleted  (ON DELETE RESTRICT)
DO $$ BEGIN
    DELETE FROM mitre_technique WHERE technique_id = 'T1486';
    RAISE NOTICE 'TEST 19 FAILED: technique used by a detection rule was deleted';
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'TEST 19 PASSED (delete of technique in use blocked): %', SQLERRM;
END $$;
