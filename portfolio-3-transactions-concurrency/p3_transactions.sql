-- =====================================================================
-- MIT 8103 — Portfolio 3: Transactions and Concurrency Control
-- Case study: CyberAce Tech Security Ltd (SOC database)
-- Run AFTER Portfolio 1 scripts, in the pgAdmin Query Tool (F5).
--   * Messages tab    -> step-by-step narration of each demo
--   * Data Output tab -> final state proving what committed / rolled back
-- Re-runnable: resets incidents 4 and 5 at the start.
-- =====================================================================

-- Reset the two NEW, unassigned incidents used in these demos
DELETE FROM remediation_task WHERE incident_id IN (4, 5);
DELETE FROM audit_log WHERE entity_type = 'incident' AND entity_id IN (4, 5);
UPDATE incident SET assigned_analyst_id = NULL, status = 'New', closed_at = NULL
WHERE incident_id IN (4, 5);


-- =====================================================================
-- DEMO 1 — ATOMICITY (success): escalating an incident is 3 writes that
-- must succeed together: claim incident + create task + audit entry.
-- =====================================================================
DO $$
BEGIN
    UPDATE incident SET assigned_analyst_id = 3, status = 'In Progress' WHERE incident_id = 4;
    INSERT INTO remediation_task (incident_id, analyst_id, description, due_date)
    VALUES (4, 3, 'Isolate nl-ws-ops03 and collect forensic image', '2026-11-14');
    INSERT INTO audit_log (analyst_id, action, entity_type, entity_id)
    VALUES (3, 'CLAIM_INCIDENT', 'incident', 4);
    RAISE NOTICE 'DEMO 1: incident 4 claimed + task + audit entry -> all 3 writes COMMITTED together';
END $$;


-- =====================================================================
-- DEMO 2 — ATOMICITY (failure + ROLLBACK): the 3rd write fails
-- (task has no due date -> NOT NULL violation), so the WHOLE unit is
-- rolled back, including the incident claim that had already succeeded.
-- =====================================================================
DO $$
BEGIN
    BEGIN   -- inner block = a transaction unit (savepoint)
        UPDATE incident SET assigned_analyst_id = 4, status = 'In Progress' WHERE incident_id = 5;
        RAISE NOTICE 'DEMO 2: step 1 OK - incident 5 claimed by analyst 4 (not yet committed)';
        INSERT INTO audit_log (analyst_id, action, entity_type, entity_id)
        VALUES (4, 'CLAIM_INCIDENT', 'incident', 5);
        RAISE NOTICE 'DEMO 2: step 2 OK - audit entry written (not yet committed)';
        INSERT INTO remediation_task (incident_id, analyst_id, description, due_date)
        VALUES (5, 4, 'Task with missing due date', NULL);       -- fails
        RAISE NOTICE 'DEMO 2: step 3 OK (should never print)';
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'DEMO 2: step 3 FAILED (%) -> ROLLBACK of steps 1-3', SQLERRM;
    END;
    RAISE NOTICE 'DEMO 2: incident 5 assigned analyst after rollback = % (NULL means rollback worked)',
        (SELECT assigned_analyst_id FROM incident WHERE incident_id = 5);
END $$;


-- =====================================================================
-- DEMO 3 — SAVEPOINT (partial rollback): keep the good work, undo only
-- the failed optional step.
-- =====================================================================
DO $$
BEGIN
    INSERT INTO audit_log (analyst_id, action, entity_type, entity_id)
    VALUES (1, 'VIEW_INCIDENT', 'incident', 5);
    RAISE NOTICE 'DEMO 3: audit entry written (kept)';
    BEGIN   -- savepoint
        UPDATE incident SET severity = 'Extreme' WHERE incident_id = 5;   -- violates CHECK
    EXCEPTION WHEN OTHERS THEN
        RAISE NOTICE 'DEMO 3: severity change rejected (%) -> rolled back to savepoint only', SQLERRM;
    END;
    RAISE NOTICE 'DEMO 3: audit entry still present = %',
        (SELECT COUNT(*) FROM audit_log WHERE action = 'VIEW_INCIDENT' AND entity_id = 5);
END $$;


-- =====================================================================
-- DEMO 4 — CONCURRENCY: the LOST UPDATE problem and its fix.
-- Two L2 analysts (Fatima = 3, Kwame = 4) open incident 5 at the same
-- moment and both click "Claim".
-- =====================================================================
DO $$
DECLARE seen_by_fatima INT; seen_by_kwame INT; rows_fatima INT; rows_kwame INT;
BEGIN
    -- ---- (a) UNSAFE pattern: read, then blindly write -----------------
    SELECT assigned_analyst_id INTO seen_by_fatima FROM incident WHERE incident_id = 5;
    SELECT assigned_analyst_id INTO seen_by_kwame  FROM incident WHERE incident_id = 5;
    RAISE NOTICE 'DEMO 4a: both analysts read incident 5 -> assigned = % / % (both think it is free)',
        COALESCE(seen_by_fatima::TEXT, 'NULL'), COALESCE(seen_by_kwame::TEXT, 'NULL');
    UPDATE incident SET assigned_analyst_id = 3 WHERE incident_id = 5;   -- Fatima writes
    UPDATE incident SET assigned_analyst_id = 4 WHERE incident_id = 5;   -- Kwame overwrites
    RAISE NOTICE 'DEMO 4a: final owner = analyst % -> Fatima''s claim was silently LOST (lost update)',
        (SELECT assigned_analyst_id FROM incident WHERE incident_id = 5);

    UPDATE incident SET assigned_analyst_id = NULL WHERE incident_id = 5;   -- reset

    -- ---- (b) SAFE pattern: conditional (optimistic) update -------------
    UPDATE incident SET assigned_analyst_id = 3, status = 'In Progress'
    WHERE  incident_id = 5 AND assigned_analyst_id IS NULL;
    GET DIAGNOSTICS rows_fatima = ROW_COUNT;
    UPDATE incident SET assigned_analyst_id = 4, status = 'In Progress'
    WHERE  incident_id = 5 AND assigned_analyst_id IS NULL;
    GET DIAGNOSTICS rows_kwame = ROW_COUNT;
    RAISE NOTICE 'DEMO 4b: Fatima''s claim updated % row(s); Kwame''s claim updated % row(s)', rows_fatima, rows_kwame;
    RAISE NOTICE 'DEMO 4b: final owner = analyst % -> second claim REJECTED, no lost update',
        (SELECT assigned_analyst_id FROM incident WHERE incident_id = 5);
END $$;


-- =====================================================================
-- DEMO 5 — PESSIMISTIC LOCKING with SELECT ... FOR UPDATE (row lock)
-- and the current isolation level.
-- The real two-session blocking demo is in README.md (two Query Tool tabs).
-- =====================================================================
DO $$
DECLARE owner INT;
BEGIN
    SELECT assigned_analyst_id INTO owner FROM incident WHERE incident_id = 4 FOR UPDATE;
    RAISE NOTICE 'DEMO 5: incident 4 row LOCKED with FOR UPDATE (owner = %); other sessions must wait until COMMIT',
        owner;
    RAISE NOTICE 'DEMO 5: default isolation level = %', current_setting('transaction_isolation');
END $$;


-- =====================================================================
-- FINAL STATE (Data Output tab)
-- =====================================================================
SELECT i.incident_id,
       i.title,
       i.status,
       an.full_name AS assigned_to,
       (SELECT COUNT(*) FROM remediation_task t WHERE t.incident_id = i.incident_id) AS tasks,
       (SELECT COUNT(*) FROM audit_log l WHERE l.entity_type = 'incident'
                                         AND l.entity_id = i.incident_id)            AS audit_entries
FROM   incident i
LEFT   JOIN analyst an ON an.analyst_id = i.assigned_analyst_id
WHERE  i.incident_id IN (4, 5)
ORDER  BY i.incident_id;
