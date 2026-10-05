# Convention de stockage S3 — ACIP

Bucket cible : `acip-evidence` (5 Go gratuits en AWS Free Tier)

## Structure des préfixes

```
s3://acip-evidence/
  raw-events/{source_type}/{yyyy}/{mm}/{dd}/{incident_id}.json
  evidence/{case_id}/{data_source_type}/{filename}
  reports/{case_id}/{report_type}_{timestamp}.{ext}
  exports/{case_id}/export_{timestamp}.{ext}
```

## Règle d'or

**Ne jamais construire un chemin S3 à la main.** Utiliser systématiquement les fonctions du
module `s3_paths.py` (`raw_event_path`, `evidence_path`, `report_path`, `export_path`,
`full_s3_uri`). Cela garantit un format unique, exploitable de façon prévisible par le dashboard,
les futurs exports, et les règles de cycle de vie ci-dessous.

## Qui écrit où

| Préfixe | Écrit par | Exemple de contenu |
|---|---|---|
| `raw-events/` | Ingestion Service | Événement CloudTrail brut, avant normalisation |
| `evidence/` | AWS Collector, Correlation Worker | Logs enrichis, captures d'état de ressource |
| `reports/` | AI Analysis Worker | Résumé PDF, timeline exportée |
| `exports/` | Backend API (à la demande d'un analyste) | Export CSV ponctuel depuis le dashboard |

## Cycle de vie (voir `s3_lifecycle_policy.json`)

| Préfixe | Transition Glacier | Expiration |
|---|---|---|
| `raw-events/` | 30 jours | 90 jours |
| `evidence/` | 60 jours | Jamais (valeur probante) |
| `reports/` | 180 jours | Jamais |
| `exports/` | — | 30 jours |

## Validation (Phase 1)

Confirmé fonctionnel via `test_phase1.py` : un chemin `evidence/{case_id}/cloudtrail/events.json`
a été généré et associé avec succès à un `Evidence` en base de données (voir rapport Phase 1).