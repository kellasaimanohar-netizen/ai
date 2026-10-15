-- Informational findings were never counted when a test was saved, so info_count was always 0.
-- Fill it in from the stored findings. Skipped checks are not counted, matching the audit engine.
UPDATE normal_agent_tests t SET info_count = sub.n
FROM (SELECT normal_test_id, COUNT(*) AS n FROM audit_findings
      WHERE normal_test_id IS NOT NULL AND UPPER(severity) = 'INFO' AND COALESCE(description, '') NOT LIKE 'Skipped:%'
      GROUP BY normal_test_id) sub
WHERE sub.normal_test_id = t.id AND COALESCE(t.info_count, 0) = 0;

UPDATE live_agent_tests t SET info_count = sub.n
FROM (SELECT live_test_id, COUNT(*) AS n FROM audit_findings
      WHERE live_test_id IS NOT NULL AND UPPER(severity) IN ('INFO', 'LOW')
      GROUP BY live_test_id) sub
WHERE sub.live_test_id = t.id AND COALESCE(t.info_count, 0) = 0;
