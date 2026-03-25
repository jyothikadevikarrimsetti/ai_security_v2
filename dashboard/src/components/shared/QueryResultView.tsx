import React from 'react';
import {
  Shield,
  AlertTriangle,
  Search,
  Brain,
  CheckCircle2,
  XCircle,
  Database,
  FileCode,
  Activity,
  Eye,
  Fingerprint,
  Zap,
  Lock,
  ScrollText,
} from 'lucide-react';
import { GatewayQueryResponse } from '../../types/queryvault';
import { StatusBadge } from './StatusBadge';
import { JsonViewer } from './JsonViewer';
import { CollapsibleSection } from './CollapsibleSection';

/* ── Helpers ─────────────────────────────────────────────── */

function riskColor(score: number): string {
  if (score < 0.3) return 'bg-green-500';
  if (score < 0.6) return 'bg-yellow-500';
  return 'bg-red-500';
}

function riskBgColor(score: number): string {
  if (score < 0.3) return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
  if (score < 0.6) return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
  return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
}

function riskLabel(score: number): string {
  if (score < 0.3) return 'text-green-700 dark:text-green-400';
  if (score < 0.6) return 'text-yellow-700 dark:text-yellow-400';
  return 'text-red-700 dark:text-red-400';
}

function riskText(score: number): string {
  if (score < 0.1) return 'Very Low';
  if (score < 0.3) return 'Low';
  if (score < 0.6) return 'Medium';
  if (score < 0.8) return 'High';
  return 'Critical';
}

function threatColor(level: string): string {
  const upper = level.toUpperCase();
  if (upper === 'NONE') return 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800';
  if (upper === 'LOW') return 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800';
  if (upper === 'MEDIUM') return 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800';
  if (upper === 'HIGH') return 'bg-orange-50 dark:bg-orange-900/20 border-orange-200 dark:border-orange-800';
  return 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800';
}

function threatIconColor(level: string): string {
  const upper = level.toUpperCase();
  if (upper === 'NONE') return 'text-green-500';
  if (upper === 'LOW') return 'text-blue-500';
  if (upper === 'MEDIUM') return 'text-yellow-500';
  if (upper === 'HIGH') return 'text-orange-500';
  return 'text-red-500';
}

function gateDisplayName(gate: string): string {
  const map: Record<string, string> = {
    syntax: 'Gate 1: Syntax',
    semantic: 'Gate 2: Semantic',
    permission: 'Gate 3: Permission',
  };
  return map[gate] ?? gate;
}

const ZONE_LABELS: Record<string, { label: string; icon: React.FC<{ className?: string }> }> = {
  PRE_MODEL: { label: 'Pre-Model', icon: Shield },
  MODEL_BOUNDARY: { label: 'Model Boundary', icon: Brain },
  POST_MODEL: { label: 'Post-Model', icon: CheckCircle2 },
  EXECUTION: { label: 'Execution', icon: Database },
  CONTINUOUS: { label: 'Continuous Audit', icon: Activity },
};

const ALL_ZONES = ['PRE_MODEL', 'MODEL_BOUNDARY', 'POST_MODEL', 'EXECUTION', 'CONTINUOUS'];

/* ── Component ───────────────────────────────────────────── */

interface QueryResultViewProps {
  data: GatewayQueryResponse;
  rawJson?: string;
}

export const QueryResultView: React.FC<QueryResultViewProps> = ({ data, rawJson }) => {
  const sec = data.security_summary;

  return (
    <div className="space-y-5">

      {/* ── Blocked / Error Banner ──────────────────── */}
      {data.blocked_reason && (
        <div className="bg-red-50 dark:bg-red-900/20 border-2 border-red-300 dark:border-red-700 rounded-xl p-5">
          <div className="flex items-center gap-3 mb-2">
            <XCircle className="w-6 h-6 text-red-500" />
            <StatusBadge value="BLOCKED" />
            <span className="text-sm font-semibold text-red-800 dark:text-red-200">Access Denied</span>
          </div>
          <p className="text-sm text-red-700 dark:text-red-300 ml-9">{data.blocked_reason}</p>
        </div>
      )}

      {data.error && !data.blocked_reason && (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-yellow-500" />
            <p className="text-sm text-yellow-700 dark:text-yellow-300">{data.error}</p>
          </div>
        </div>
      )}

      {/* ── Zone Progress Pipeline ──────────────────── */}
      {sec && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 shadow-sm">
          <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-4">
            Security Zone Pipeline
          </h3>
          <div className="flex items-center gap-1">
            {ALL_ZONES.map((zone, idx) => {
              const passed = sec.zones_passed.includes(zone);
              const info = ZONE_LABELS[zone];
              const Icon = info?.icon ?? Shield;
              return (
                <div key={zone} className="flex items-center gap-1 flex-1">
                  <div
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg flex-1 transition-all ${
                      passed
                        ? 'bg-green-50 dark:bg-green-900/30 border border-green-200 dark:border-green-800'
                        : 'bg-gray-100 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 opacity-50'
                    }`}
                  >
                    <Icon className={`w-4 h-4 ${passed ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`} />
                    <div>
                      <p className={`text-[10px] font-semibold ${passed ? 'text-green-700 dark:text-green-300' : 'text-gray-500'}`}>
                        {info?.label ?? zone}
                      </p>
                      <p className={`text-[9px] ${passed ? 'text-green-600 dark:text-green-400' : 'text-gray-400'}`}>
                        {passed ? 'PASSED' : 'SKIPPED'}
                      </p>
                    </div>
                  </div>
                  {idx < ALL_ZONES.length - 1 && (
                    <div className={`w-4 h-0.5 ${passed ? 'bg-green-400' : 'bg-gray-300 dark:bg-gray-600'}`} />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── Security Overview Cards (2x2 grid) ─────── */}
      {sec && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">

          {/* Card 1: Injection Risk Score */}
          <div className={`rounded-xl border p-4 ${riskBgColor(sec.pre_model.injection_risk_score)}`}>
            <div className="flex items-center gap-2 mb-3">
              <Shield className={`w-4 h-4 ${riskLabel(sec.pre_model.injection_risk_score)}`} />
              <span className="text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Injection Risk
              </span>
            </div>
            <div className="flex items-baseline gap-2 mb-2">
              <span className={`text-2xl font-bold ${riskLabel(sec.pre_model.injection_risk_score)}`}>
                {(sec.pre_model.injection_risk_score * 100).toFixed(0)}%
              </span>
              <span className={`text-xs font-medium ${riskLabel(sec.pre_model.injection_risk_score)}`}>
                {riskText(sec.pre_model.injection_risk_score)}
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5">
              <div
                className={`${riskColor(sec.pre_model.injection_risk_score)} h-2.5 rounded-full transition-all`}
                style={{ width: `${Math.max(Math.min(sec.pre_model.injection_risk_score * 100, 100), 2)}%` }}
              />
            </div>
            {sec.pre_model.injection_flags.length > 0 && (
              <p className="text-[10px] text-gray-500 dark:text-gray-400 mt-2 truncate">
                {sec.pre_model.injection_flags.length} pattern(s) matched
              </p>
            )}
          </div>

          {/* Card 2: Threat Level */}
          <div className={`rounded-xl border p-4 ${threatColor(sec.threat_level)}`}>
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className={`w-4 h-4 ${threatIconColor(sec.threat_level)}`} />
              <span className="text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Threat Level
              </span>
            </div>
            <div className="flex items-center gap-3 mb-1">
              <StatusBadge value={sec.threat_level} />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
              {sec.threat_level === 'NONE'
                ? 'No threats detected'
                : sec.pre_model.threat_category
                  ? `Category: ${sec.pre_model.threat_category}`
                  : 'Threat detected'}
            </p>
          </div>

          {/* Card 3: Probing Detection */}
          <div className={`rounded-xl border p-4 ${
            sec.pre_model.probing_detected
              ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
              : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
          }`}>
            <div className="flex items-center gap-2 mb-3">
              <Search className={`w-4 h-4 ${sec.pre_model.probing_detected ? 'text-red-500' : 'text-green-500'}`} />
              <span className="text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Probing Detection
              </span>
            </div>
            <div className="flex items-center gap-2 mb-1">
              <StatusBadge value={sec.pre_model.probing_detected ? 'DETECTED' : 'NONE'} />
            </div>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
              {sec.pre_model.probing_detected
                ? `Score: ${(sec.pre_model.probing_score * 100).toFixed(0)}%`
                : 'No schema reconnaissance detected'}
            </p>
          </div>

          {/* Card 4: Behavioral Analysis */}
          <div className={`rounded-xl border p-4 ${
            sec.pre_model.behavioral_anomaly_score >= 0.7
              ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
              : sec.pre_model.behavioral_anomaly_score >= 0.4
                ? 'bg-yellow-50 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
                : 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
          }`}>
            <div className="flex items-center gap-2 mb-3">
              <Fingerprint className={`w-4 h-4 ${
                sec.pre_model.behavioral_anomaly_score >= 0.7
                  ? 'text-red-500'
                  : sec.pre_model.behavioral_anomaly_score >= 0.4
                    ? 'text-yellow-500'
                    : 'text-green-500'
              }`} />
              <span className="text-xs font-semibold text-gray-600 dark:text-gray-300 uppercase tracking-wider">
                Behavioral
              </span>
            </div>
            <div className="flex items-baseline gap-2 mb-1">
              <span className="text-2xl font-bold text-gray-800 dark:text-gray-200">
                {(sec.pre_model.behavioral_anomaly_score * 100).toFixed(0)}%
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-400">anomaly</span>
            </div>
            {sec.pre_model.behavioral_flags.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-2">
                {sec.pre_model.behavioral_flags.map((flag, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] bg-gray-200 dark:bg-gray-600 text-gray-700 dark:text-gray-200"
                  >
                    {flag}
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Injection Flags Detail ─────────────────── */}
      {sec && sec.pre_model.injection_flags.length > 0 && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-red-500" />
            <h3 className="text-sm font-semibold text-red-800 dark:text-red-200">
              Injection Patterns Detected ({sec.pre_model.injection_flags.length})
            </h3>
          </div>
          <div className="space-y-1.5">
            {sec.pre_model.injection_flags.map((flag, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-red-700 dark:text-red-300">
                <XCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                <span>{flag}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Generated SQL ───────────────────────────── */}
      {data.sql && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 shadow-sm">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <FileCode className="w-4 h-4 text-blue-500" />
              <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Generated SQL
              </h3>
            </div>
            {sec?.validation_result && <StatusBadge value={sec.validation_result} />}
          </div>
          <pre className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-4 overflow-x-auto">
            <code className="text-sm font-mono text-gray-800 dark:text-gray-200 whitespace-pre-wrap">{data.sql}</code>
          </pre>
        </div>
      )}

      {/* ── Gate Results (Post-Model Validation) ────── */}
      {sec && Object.keys(sec.post_model.gate_results).length > 0 && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Lock className="w-4 h-4 text-purple-500" />
            <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Post-Model Validation Gates
            </h3>
            <StatusBadge value={sec.post_model.validation_decision || 'PENDING'} />
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {Object.entries(sec.post_model.gate_results).map(([gate, status]) => {
              const passed = status.toUpperCase() === 'PASS';
              return (
                <div
                  key={gate}
                  className={`rounded-lg border p-4 text-center ${
                    passed
                      ? 'bg-green-50 dark:bg-green-900/20 border-green-200 dark:border-green-800'
                      : 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
                  }`}
                >
                  <div className="flex justify-center mb-2">
                    {passed ? (
                      <CheckCircle2 className="w-6 h-6 text-green-500" />
                    ) : (
                      <XCircle className="w-6 h-6 text-red-500" />
                    )}
                  </div>
                  <p className="text-sm font-semibold text-gray-800 dark:text-gray-200">
                    {gateDisplayName(gate)}
                  </p>
                  <StatusBadge value={status} />
                </div>
              );
            })}
          </div>

          {/* Hallucination Detection */}
          <div className="mt-4 pt-3 border-t border-gray-200 dark:border-gray-700 flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4 text-gray-400" />
              <span className="text-xs text-gray-500 dark:text-gray-400">Hallucination:</span>
              <StatusBadge value={sec.post_model.hallucination_detected ? 'DETECTED' : 'NONE'} />
            </div>
            {sec.post_model.hallucinated_identifiers.length > 0 && (
              <div className="flex items-center gap-1">
                <span className="text-xs text-red-600 dark:text-red-400">
                  Hallucinated: {sec.post_model.hallucinated_identifiers.join(', ')}
                </span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-500 dark:text-gray-400">Violations:</span>
              <span className={`text-sm font-semibold ${
                sec.post_model.violations.length > 0
                  ? 'text-red-600 dark:text-red-400'
                  : 'text-green-600 dark:text-green-400'
              }`}>
                {sec.post_model.violations.length}
              </span>
            </div>
          </div>

          {/* Violation details */}
          {sec.post_model.violations.length > 0 && (
            <div className="mt-3">
              <p className="text-xs font-medium text-red-600 dark:text-red-400 mb-1">Violations:</p>
              <div className="space-y-1">
                {sec.post_model.violations.map((v: any, i: number) => (
                  <div key={i} className="flex items-start gap-2 text-xs text-red-700 dark:text-red-300 bg-red-50 dark:bg-red-900/10 rounded px-2 py-1">
                    <XCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                    <span>{v.detail || v.rule || JSON.stringify(v)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Query Rewriting ─────────────────────────── */}
      {sec && sec.post_model.rewrites_applied.length > 0 && (
        <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <ScrollText className="w-4 h-4 text-purple-500" />
            <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Query Rewriting Applied
            </h3>
            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-purple-100 text-purple-800 dark:bg-purple-800 dark:text-purple-200">
              {sec.post_model.rewrites_applied.length} rewrite(s)
            </span>
          </div>
          <div className="space-y-2">
            {sec.post_model.rewrites_applied.map((rw, i) => (
              <div key={i} className="flex items-start gap-2 bg-white dark:bg-gray-800 rounded-lg px-3 py-2 border border-purple-100 dark:border-purple-800">
                <Zap className="w-3.5 h-3.5 mt-0.5 text-purple-500 flex-shrink-0" />
                <span className="text-sm text-gray-700 dark:text-gray-300">{rw}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Execution Metrics ──────────────────────── */}
      {sec?.execution && (
        <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Database className="w-4 h-4 text-emerald-500" />
            <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
              Execution Metrics
            </h3>
            <StatusBadge value={sec.execution_status || 'SUCCESS'} />
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Rows Returned</p>
              <p className="text-xl font-bold text-gray-800 dark:text-gray-200">{sec.execution.rows_returned}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Latency</p>
              <p className="text-xl font-bold text-gray-800 dark:text-gray-200">{sec.execution.execution_latency_ms}ms</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Sanitization</p>
              <div className="mt-1">
                <StatusBadge value={sec.execution.sanitization_applied ? 'APPLIED' : 'NONE'} />
              </div>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400 mb-1">Resource Limits</p>
              <div className="mt-1">
                <StatusBadge value={sec.execution.resource_limits_hit ? 'HIT' : 'OK'} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Query Results Data Table ─────────────────── */}
      {data.results && (() => {
        const columns: string[] = data.results.columns ?? [];
        const rows: Record<string, any>[] = data.results.rows ?? [];
        const execError: string | undefined = data.results.error || sec?.execution?.data?.error;
        const hasData = columns.length > 0 && rows.length > 0;

        return (
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 shadow-sm overflow-hidden">
            <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 dark:border-gray-800">
              <div className="flex items-center gap-2">
                <Database className="w-4 h-4 text-blue-500" />
                <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                  Query Results
                </h3>
              </div>
              {hasData && (
                <span className="text-xs text-gray-500 dark:text-gray-400">
                  {rows.length} row{rows.length !== 1 ? 's' : ''} · {columns.length} column{columns.length !== 1 ? 's' : ''}
                </span>
              )}
            </div>

            {/* Execution error banner */}
            {execError && (
              <div className="mx-5 mt-4 mb-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3">
                <div className="flex items-start gap-2">
                  <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-xs font-semibold text-red-700 dark:text-red-300 mb-0.5">Execution Error</p>
                    <p className="text-xs text-red-600 dark:text-red-400 font-mono">{execError}</p>
                  </div>
                </div>
              </div>
            )}

            {/* Data table */}
            {hasData && (
              <div className="overflow-x-auto max-h-[500px] overflow-y-auto">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 dark:bg-gray-800 sticky top-0 z-10">
                    <tr>
                      <th className="px-3 py-2 text-left text-[10px] font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider border-b border-gray-200 dark:border-gray-700 w-10">
                        #
                      </th>
                      {columns.map((col: string) => (
                        <th
                          key={col}
                          className="px-3 py-2 text-left text-[10px] font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider border-b border-gray-200 dark:border-gray-700 whitespace-nowrap"
                        >
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-gray-800">
                    {rows.map((row: Record<string, any>, idx: number) => (
                      <tr
                        key={idx}
                        className={idx % 2 === 0 ? 'bg-white dark:bg-gray-900' : 'bg-gray-50/50 dark:bg-gray-800/30'}
                      >
                        <td className="px-3 py-1.5 text-xs text-gray-400 dark:text-gray-500 font-mono">
                          {idx + 1}
                        </td>
                        {columns.map((col: string) => {
                          const val = row[col];
                          const display =
                            val === null || val === undefined
                              ? '—'
                              : typeof val === 'object'
                                ? JSON.stringify(val)
                                : String(val);
                          return (
                            <td
                              key={col}
                              className="px-3 py-1.5 text-xs text-gray-700 dark:text-gray-300 whitespace-nowrap max-w-[300px] truncate"
                              title={display}
                            >
                              {val === null || val === undefined ? (
                                <span className="text-gray-300 dark:text-gray-600 italic">null</span>
                              ) : (
                                display
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Empty state (no error, just no rows) */}
            {!hasData && !execError && (
              <div className="px-5 py-8 text-center">
                <Database className="w-8 h-8 text-gray-300 dark:text-gray-600 mx-auto mb-2" />
                <p className="text-sm text-gray-400 dark:text-gray-500">Query executed successfully but returned no rows</p>
                <p className="text-xs text-gray-300 dark:text-gray-600 mt-1">Try broadening your query criteria</p>
              </div>
            )}
          </div>
        );
      })()}

      {/* ── Audit Footer + Raw JSON ────────────────── */}
      {(data.audit_id || data.request_id) && (
        <div className="flex items-center justify-between pt-2 text-xs text-gray-400 dark:text-gray-500">
          {data.audit_id && (
            <span>Audit ID: <span className="font-mono">{data.audit_id}</span></span>
          )}
          {data.request_id && (
            <span>Request ID: <span className="font-mono">{data.request_id}</span></span>
          )}
        </div>
      )}

      {rawJson && (
        <div className="mt-4">
          <CollapsibleSection title="Raw Response">
            <JsonViewer rawJson={rawJson} />
          </CollapsibleSection>
        </div>
      )}
    </div>
  );
};
