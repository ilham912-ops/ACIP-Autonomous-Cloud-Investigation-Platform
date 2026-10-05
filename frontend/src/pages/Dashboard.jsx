import React, { useEffect, useState } from 'react';
import {
  FiShield,
  FiAlertTriangle,
  FiClock,
  FiCheckCircle,
  FiXCircle,
  FiActivity,
  FiRefreshCw,
  FiDatabase,
  FiChevronRight,
} from 'react-icons/fi';

import { dashboardAPI } from '../services/api';
import websocketService from '../services/websocket';

const Dashboard = () => {
  const [dashboard, setDashboard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [isConnected, setIsConnected] = useState(false);
  const [error, setError] = useState(null);

  const loadDashboard = async () => {
    try {
      setError(null);
      setRefreshing(true);

      const data = await dashboardAPI.getSummary();
      setDashboard(data);
    } catch (err) {
      console.error('Error loading dashboard:', err);
      setError(
        err?.response?.data?.detail ||
        'Impossible de charger les données du dashboard.'
      );
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadDashboard();

    const onConnected = () => setIsConnected(true);
    const onDisconnected = () => setIsConnected(false);

    websocketService.on('connected', onConnected);
    websocketService.on('disconnected', onDisconnected);

    if (!websocketService.isConnected) {
      websocketService.connect();
    } else {
      setIsConnected(true);
    }

    return () => {
      websocketService.off('connected', onConnected);
      websocketService.off('disconnected', onDisconnected);
    };
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center">
          <FiShield className="mx-auto text-4xl text-cyan-400 animate-pulse mb-4" />
          <p className="text-slate-300">Chargement du Security Dashboard...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen bg-slate-950 p-8">
        <div className="max-w-3xl mx-auto bg-red-950/40 border border-red-800 rounded-xl p-6">
          <div className="flex items-center gap-3">
            <FiAlertTriangle className="text-red-400 text-2xl" />
            <div>
              <h2 className="text-white font-semibold">
                Erreur de chargement
              </h2>
              <p className="text-red-300 mt-1">{error}</p>
            </div>
          </div>

          <button
            onClick={loadDashboard}
            className="mt-5 px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg"
          >
            Réessayer
          </button>
        </div>
      </div>
    );
  }

  const volumeBySource = dashboard?.volume_by_data_source || [];
  const pendingFindings = dashboard?.pending_findings || [];
  const falsePositiveRate = dashboard?.false_positive_rate || {};
  const mtti = dashboard?.mtti || {};
  const caseStatus = dashboard?.case_status_breakdown || [];

  const totalFindings = volumeBySource.reduce(
    (sum, item) => sum + Number(item.findings_count || 0),
    0
  );

  const totalPending = pendingFindings.reduce(
    (sum, item) => sum + Number(item.pending_count || 0),
    0
  );

  const openCases = caseStatus
    .filter((item) => String(item.status).toLowerCase() === 'open')
    .reduce((sum, item) => sum + Number(item.case_count || 0), 0);

  const falsePositives = Number(falsePositiveRate.false_positives || 0);

  const sourceMax = Math.max(
    ...volumeBySource.map((item) => Number(item.findings_count || 0)),
    1
  );

  const pendingMax = Math.max(
    ...pendingFindings.map((item) => Number(item.pending_count || 0)),
    1
  );

  const formatSource = (source) => {
    if (!source) return 'Unknown';

    return source
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  };

  const formatFindingType = (type) => {
    if (!type) return 'Unknown';

    return type
      .replace(/_/g, ' ')
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  };

  const formatSeverity = (severity) => {
    return String(severity || 'unknown').toUpperCase();
  };

  const severityClass = (severity) => {
    const value = String(severity || '').toLowerCase();

    if (value === 'critical') {
      return 'bg-red-500/15 text-red-400 border-red-500/30';
    }

    if (value === 'high') {
      return 'bg-orange-500/15 text-orange-400 border-orange-500/30';
    }

    if (value === 'medium') {
      return 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30';
    }

    return 'bg-slate-500/15 text-slate-300 border-slate-500/30';
  };

  return (
    <div className="min-h-screen bg-slate-950 text-white">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

        {/* HEADER */}
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <div className="flex items-center gap-3">
              <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 rounded-xl">
                <FiShield className="text-cyan-400 text-2xl" />
              </div>

              <div>
                <h1 className="text-3xl font-bold tracking-tight">
                  ACIP Security Dashboard
                </h1>

                <p className="text-slate-400 mt-1">
                  Autonomous Cloud Investigation Platform
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800">
              <span
                className={`w-2.5 h-2.5 rounded-full ${
                  isConnected
                    ? 'bg-emerald-400 animate-pulse'
                    : 'bg-red-500'
                }`}
              />

              <span className="text-sm text-slate-300">
                {isConnected ? 'Live' : 'Disconnected'}
              </span>
            </div>

            <button
              onClick={loadDashboard}
              disabled={refreshing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-900 border border-slate-800 hover:bg-slate-800 transition disabled:opacity-50"
            >
              <FiRefreshCw
                className={refreshing ? 'animate-spin' : ''}
              />
              Actualiser
            </button>
          </div>
        </div>

        {/* KPI CARDS */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5 mb-8">

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm">
                  Findings actifs
                </p>

                <p className="text-3xl font-bold mt-2">
                  {totalFindings}
                </p>

                <p className="text-xs text-slate-500 mt-2">
                  IAM + CloudTrail
                </p>
              </div>

              <div className="p-3 rounded-xl bg-cyan-500/10">
                <FiAlertTriangle className="text-cyan-400 text-xl" />
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm">
                  À analyser
                </p>

                <p className="text-3xl font-bold mt-2">
                  {totalPending}
                </p>

                <p className="text-xs text-orange-400 mt-2">
                  Findings en attente
                </p>
              </div>

              <div className="p-3 rounded-xl bg-orange-500/10">
                <FiActivity className="text-orange-400 text-xl" />
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm">
                  Investigations ouvertes
                </p>

                <p className="text-3xl font-bold mt-2">
                  {openCases}
                </p>

                <p className="text-xs text-blue-400 mt-2">
                  Cases actifs
                </p>
              </div>

              <div className="p-3 rounded-xl bg-blue-500/10">
                <FiDatabase className="text-blue-400 text-xl" />
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-slate-400 text-sm">
                  Faux positifs
                </p>

                <p className="text-3xl font-bold mt-2">
                  {falsePositives}
                </p>

                <p className="text-xs text-red-400 mt-2">
                  Taux : {falsePositiveRate.false_positive_rate_pct ?? 0}%
                </p>
              </div>

              <div className="p-3 rounded-xl bg-red-500/10">
                <FiXCircle className="text-red-400 text-xl" />
              </div>
            </div>
          </div>
        </div>

        {/* MAIN GRID */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">

          {/* FINDINGS BY SOURCE */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold">
                  Findings par source
                </h2>

                <p className="text-sm text-slate-500 mt-1">
                  Distribution des événements détectés
                </p>
              </div>

              <FiDatabase className="text-slate-500" />
            </div>

            <div className="space-y-5">
              {volumeBySource.length === 0 ? (
                <p className="text-slate-500">
                  Aucune donnée disponible.
                </p>
              ) : (
                volumeBySource.map((item) => {
                  const count = Number(item.findings_count || 0);
                  const width = `${(count / sourceMax) * 100}%`;

                  return (
                    <div key={item.data_source_type}>
                      <div className="flex justify-between mb-2">
                        <span className="text-sm text-slate-300">
                          {formatSource(item.data_source_type)}
                        </span>

                        <span className="text-sm font-semibold">
                          {count}
                        </span>
                      </div>

                      <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-500 rounded-full transition-all duration-700"
                          style={{ width }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* PENDING FINDINGS */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold">
                  Findings à analyser
                </h2>

                <p className="text-sm text-slate-500 mt-1">
                  Findings nécessitant une investigation
                </p>
              </div>

              <FiAlertTriangle className="text-orange-400" />
            </div>

            <div className="space-y-4">
              {pendingFindings.length === 0 ? (
                <p className="text-slate-500">
                  Aucun finding en attente.
                </p>
              ) : (
                pendingFindings.map((item, index) => {
                  const count = Number(item.pending_count || 0);
                  const width = `${(count / pendingMax) * 100}%`;

                  return (
                    <div
                      key={`${item.finding_type}-${item.severity}-${index}`}
                      className="p-4 bg-slate-950 rounded-xl border border-slate-800"
                    >
                      <div className="flex items-center justify-between mb-3">
                        <div>
                          <p className="font-medium">
                            {formatFindingType(item.finding_type)}
                          </p>

                          <span
                            className={`inline-flex mt-2 px-2.5 py-1 text-xs rounded-full border ${severityClass(
                              item.severity
                            )}`}
                          >
                            {formatSeverity(item.severity)}
                          </span>
                        </div>

                        <span className="text-2xl font-bold">
                          {count}
                        </span>
                      </div>

                      <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-orange-500 rounded-full transition-all duration-700"
                          style={{ width }}
                        />
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* SECURITY STATUS */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">

          {/* FALSE POSITIVE */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-3 rounded-xl bg-red-500/10">
                <FiXCircle className="text-red-400 text-xl" />
              </div>

              <div>
                <h2 className="font-semibold">
                  False Positive Rate
                </h2>

                <p className="text-sm text-slate-500">
                  Qualité des détections
                </p>
              </div>
            </div>

            <p className="text-4xl font-bold">
              {falsePositiveRate.false_positive_rate_pct ?? 0}%
            </p>

            <p className="text-sm text-slate-400 mt-2">
              {falsePositives} faux positif(s) sur{' '}
              {falsePositiveRate.reviewed_total || 0} finding(s) revu(s)
            </p>
          </div>

          {/* MTTI */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-3 rounded-xl bg-blue-500/10">
                <FiClock className="text-blue-400 text-xl" />
              </div>

              <div>
                <h2 className="font-semibold">
                  MTTI
                </h2>

                <p className="text-sm text-slate-500">
                  Mean Time To Investigate
                </p>
              </div>
            </div>

            <p className="text-4xl font-bold">
              {mtti.mtti_hours == null
                ? 'N/A'
                : `${Number(mtti.mtti_hours).toFixed(2)} h`}
            </p>

            <p className="text-sm text-slate-400 mt-2">
              {mtti.closed_cases_count || 0} investigation(s) terminée(s)
            </p>
          </div>

          {/* CASE STATUS */}
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center gap-3 mb-5">
              <div className="p-3 rounded-xl bg-emerald-500/10">
                <FiCheckCircle className="text-emerald-400 text-xl" />
              </div>

              <div>
                <h2 className="font-semibold">
                  Investigation Status
                </h2>

                <p className="text-sm text-slate-500">
                  État des investigations
                </p>
              </div>
            </div>

            <div className="space-y-3">
              {caseStatus.length === 0 ? (
                <p className="text-slate-500">
                  Aucun case disponible.
                </p>
              ) : (
                caseStatus.map((item) => (
                  <div
                    key={item.status}
                    className="flex items-center justify-between p-3 bg-slate-950 rounded-lg"
                  >
                    <span className="text-slate-300 capitalize">
                      {item.status}
                    </span>

                    <span className="font-bold">
                      {item.case_count}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* ML SECTION */}
        <div className="bg-gradient-to-r from-slate-900 to-slate-900 border border-cyan-900/50 rounded-2xl p-6 mb-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-5">

            <div className="flex items-start gap-4">
              <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                <FiActivity className="text-cyan-400 text-2xl" />
              </div>

              <div>
                <div className="flex items-center gap-3">
                  <h2 className="text-xl font-semibold">
                    ML Anomaly Detection
                  </h2>

                  <span className="px-2.5 py-1 text-xs rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                    Isolation Forest
                  </span>
                </div>

                <p className="text-slate-400 mt-2 max-w-3xl">
                  ACIP analyse les connexions IAM CloudTrail afin
                  d'identifier automatiquement les comportements
                  inhabituels à partir des caractéristiques comportementales.
                </p>

                <div className="flex flex-wrap gap-2 mt-4">
                  <span className="px-3 py-1.5 rounded-lg bg-slate-950 text-xs text-slate-300 border border-slate-800">
                    hour_of_day
                  </span>

                  <span className="px-3 py-1.5 rounded-lg bg-slate-950 text-xs text-slate-300 border border-slate-800">
                    day_of_week
                  </span>

                  <span className="px-3 py-1.5 rounded-lg bg-slate-950 text-xs text-slate-300 border border-slate-800">
                    is_new_ip
                  </span>

                  <span className="px-3 py-1.5 rounded-lg bg-slate-950 text-xs text-slate-300 border border-slate-800">
                    seconds_since_last_login
                  </span>

                  <span className="px-3 py-1.5 rounded-lg bg-slate-950 text-xs text-slate-300 border border-slate-800">
                    is_failure
                  </span>
                </div>
              </div>
            </div>

            <div className="shrink-0">
              <div className="px-5 py-4 rounded-xl bg-slate-950 border border-slate-800">
                <p className="text-xs text-slate-500">
                  Detection pipeline
                </p>

                <div className="flex items-center gap-2 mt-3 text-sm">
                  <span className="text-slate-300">
                    CloudTrail
                  </span>

                  <FiChevronRight className="text-slate-600" />

                  <span className="text-cyan-400">
                    ML
                  </span>

                  <FiChevronRight className="text-slate-600" />

                  <span className="text-orange-400">
                    Finding
                  </span>
                </div>
              </div>
            </div>

          </div>
        </div>

        {/* FOOTER */}
        <div className="text-center text-xs text-slate-600 pb-4">
          ACIP • Autonomous Cloud Investigation Platform • Security Operations
        </div>

      </div>
    </div>
  );
};

export default Dashboard;