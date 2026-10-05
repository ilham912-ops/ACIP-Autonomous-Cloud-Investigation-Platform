-- ============================================================
-- Requetes d'agregation - Dashboard Security Manager (Phase 6)
-- ============================================================

-- 1. MTTI (Mean Time to Investigate) global, en heures
--    Duree moyenne entre l'ouverture et la cloture d'un case.
SELECT
    ROUND(AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)::numeric, 2) AS mtti_hours,
    COUNT(*) AS closed_cases_count
FROM investigation_cases
WHERE closed_at IS NOT NULL;

-- 2. MTTI par playbook (identifie les investigations les plus lentes)
SELECT
    playbook_id,
    ROUND(AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)::numeric, 2) AS mtti_hours,
    COUNT(*) AS closed_cases_count
FROM investigation_cases
WHERE closed_at IS NOT NULL
GROUP BY playbook_id
ORDER BY mtti_hours DESC;

-- 3. MTTI sur les 30 derniers jours (tendance recente)
SELECT
    ROUND(AVG(EXTRACT(EPOCH FROM (closed_at - created_at)) / 3600.0)::numeric, 2) AS mtti_hours_last_30d
FROM investigation_cases
WHERE closed_at IS NOT NULL
  AND created_at >= now() - interval '30 days';

-- 4. Volume de findings par type de donnee (data_source_type)
SELECT
    data_source_type,
    COUNT(*) AS findings_count
FROM findings
GROUP BY data_source_type
ORDER BY findings_count DESC;

-- 5. Volume de findings par type de donnee ET par semaine (pour un graphe de tendance)
SELECT
    date_trunc('week', created_at) AS week_start,
    data_source_type,
    COUNT(*) AS findings_count
FROM findings
GROUP BY week_start, data_source_type
ORDER BY week_start DESC, data_source_type;

-- 6. Taux de faux positifs global
--    (necessite la colonne analyst_verdict, cf. migration 0004)
SELECT
    COUNT(*) FILTER (WHERE analyst_verdict = 'false_positive') AS false_positives,
    COUNT(*) FILTER (WHERE analyst_verdict IN ('confirmed', 'false_positive')) AS reviewed_total,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE analyst_verdict = 'false_positive')
        / NULLIF(COUNT(*) FILTER (WHERE analyst_verdict IN ('confirmed', 'false_positive')), 0),
        2
    ) AS false_positive_rate_pct
FROM findings;

-- 7. Taux de faux positifs PAR REGLE (finding_type)
--    Le plus utile operationnellement : identifie quelle regle regler en priorite.
SELECT
    finding_type,
    COUNT(*) FILTER (WHERE analyst_verdict = 'false_positive') AS false_positives,
    COUNT(*) FILTER (WHERE analyst_verdict IN ('confirmed', 'false_positive')) AS reviewed_total,
    ROUND(
        100.0 * COUNT(*) FILTER (WHERE analyst_verdict = 'false_positive')
        / NULLIF(COUNT(*) FILTER (WHERE analyst_verdict IN ('confirmed', 'false_positive')), 0),
        2
    ) AS false_positive_rate_pct
FROM findings
GROUP BY finding_type
ORDER BY false_positive_rate_pct DESC NULLS LAST;

-- 8. Findings en attente de revue (file de travail de l'analyste)
SELECT
    finding_type,
    severity,
    COUNT(*) AS pending_count
FROM findings
WHERE analyst_verdict = 'pending'
GROUP BY finding_type, severity
ORDER BY
    CASE severity
        WHEN 'critical' THEN 1
        WHEN 'high' THEN 2
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 4
    END;

-- 9. Repartition des cas par statut (vue d'ensemble rapide)
SELECT
    status,
    COUNT(*) AS case_count
FROM investigation_cases
GROUP BY status;
