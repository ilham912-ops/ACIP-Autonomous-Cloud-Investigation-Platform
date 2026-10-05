import React from "react";

/**
 * MLAnomalyCard — remplace le bloc "ML Anomaly Detection" statique
 * (description + tags de features uniquement) par de vrais chiffres,
 * sur le meme principe que les cartes False Positive Rate / MTTI deja
 * presentes dans le dashboard (Phase 6).
 *
 * Attend en props les 2 champs ajoutes a /api/dashboard/summary :
 *   ml_anomaly_stats, ml_vs_rules_convergence
 *
 * Style aligne sur le theme sombre/cyan existant du dashboard ACIP
 * (classes Tailwind -- adaptez les noms de classes si votre projet
 * n'utilise pas Tailwind, la structure JSX reste valable).
 */
export default function MLAnomalyCard({ mlStats, convergence }) {
  const {
    total_anomalies_detected = 0,
    anomalies_last_7_days = 0,
    average_confidence = null,
    reviewed_by_analyst = 0,
    precision_pct = null,
    model_status = "no_detection_yet",
  } = mlStats || {};

  const features = ["hour_of_day", "day_of_week", "is_new_ip", "seconds_since_last_login", "is_failure"];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/20 flex items-center justify-center">
            <svg className="w-5 h-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2}
                d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
          </div>
          <h3 className="text-white font-semibold text-base">ML Anomaly Detection</h3>
        </div>
        <span className="text-xs px-2 py-1 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
          Isolation Forest
        </span>
      </div>

      {model_status === "no_detection_yet" ? (
        <p className="text-slate-400 text-sm mb-4">
          Le modèle n'a encore rien détecté sur les données actuelles.
        </p>
      ) : (
        <div className="grid grid-cols-3 gap-3 mb-4">
          <div>
            <div className="text-2xl font-bold text-white">{total_anomalies_detected}</div>
            <div className="text-xs text-slate-400">anomalies détectées</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-cyan-400">{anomalies_last_7_days}</div>
            <div className="text-xs text-slate-400">sur les 7 derniers jours</div>
          </div>
          <div>
            <div className="text-2xl font-bold text-white">
              {average_confidence !== null ? average_confidence.toFixed(2) : "—"}
            </div>
            <div className="text-xs text-slate-400">confidence moyenne</div>
          </div>
        </div>
      )}

      {/* Precision : n'affiche jamais 0% par defaut tant qu'aucun retour
          analyste n'existe, pour ne pas laisser croire a tort que le
          modele est mauvais (meme principe que False Positive Rate). */}
      <div className="border-t border-slate-800 pt-3 mb-4">
        {precision_pct === null ? (
          <p className="text-slate-400 text-xs">Pas encore de retour analyste sur ce modèle.</p>
        ) : (
          <p className="text-xs text-slate-300">
            <span className="text-white font-semibold">{precision_pct}%</span> de précision confirmée
            <span className="text-slate-500"> ({reviewed_by_analyst} finding(s) relu(s))</span>
          </p>
        )}
      </div>

      {/* Carte de convergence — l'argument le plus parlant : montre que
          regles et ML se recoupent plutot que de faire doublon. */}
      {convergence && convergence.cases_flagged_by_both > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg px-3 py-2 mb-4">
          <p className="text-xs text-amber-300">
            <span className="font-semibold">{convergence.cases_flagged_by_both}</span> cas signalé(s) à la
            fois par une règle et par le modèle ML — signal de forte confiance.
          </p>
        </div>
      )}

      <p className="text-xs text-slate-500 mb-3">
        ACIP analyse les connexions IAM CloudTrail afin d'identifier automatiquement les
        comportements inhabituels à partir de caractéristiques comportementales.
      </p>

      <div className="flex flex-wrap gap-2 mb-4">
        {features.map((f) => (
          <span key={f} className="text-xs font-mono px-2 py-1 rounded-full bg-slate-800 text-cyan-300">
            {f}
          </span>
        ))}
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-500 bg-slate-950 rounded-lg px-3 py-2">
        <span>Detection pipeline</span>
        <span className="text-slate-300">CloudTrail</span>
        <span>›</span>
        <span className="text-cyan-400 font-medium">ML</span>
        <span>›</span>
        <span className="text-amber-400 font-medium">Finding</span>
      </div>
    </div>
  );
}

/**
 * Exemple d'integration dans la page Dashboard existante :
 *
 *   const [summary, setSummary] = useState(null);
 *
 *   useEffect(() => {
 *     fetch("/api/dashboard/summary")
 *       .then((r) => r.json())
 *       .then(setSummary);
 *   }, []);
 *
 *   ...
 *   {summary && (
 *     <MLAnomalyCard
 *       mlStats={summary.ml_anomaly_stats}
 *       convergence={summary.ml_vs_rules_convergence}
 *     />
 *   )}
 */
