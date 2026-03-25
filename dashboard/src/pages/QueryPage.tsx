import { useState } from 'react';
import {
  ShieldCheck,
  LogOut,
  Sun,
  Moon,
  Send,
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
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../hooks/useTheme';
import { useApiCall } from '../hooks/useApiCall';
import { gatewayQuery } from '../api/queryvault';
import { GatewayQueryResponse } from '../types/queryvault';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { StatusBadge } from '../components/shared/StatusBadge';
import { JsonViewer } from '../components/shared/JsonViewer';
import { DataTable } from '../components/shared/DataTable';
import { CollapsibleSection } from '../components/shared/CollapsibleSection';
import { CLEARANCE_BADGE } from '../constants/userCategories';

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

export function QueryPage() {
  const { auth, logout } = useAuth();
  const { isDark, toggle } = useTheme();
  const { loading, result, execute } = useApiCall<GatewayQueryResponse>();
  const [question, setQuestion] = useState('');

  if (!auth) return null;
  const { user, jwt } = auth;
  const badge = CLEARANCE_BADGE[user.clearance_level] ?? CLEARANCE_BADGE[1];

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!question.trim()) return;
    execute(() => gatewayQuery({ question, jwt_token: jwt }));
  };

  const data = result?.data;
  const sec = data?.security_summary;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex flex-col">
      {/* Top Bar */}
      <header className="h-14 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-5 h-5 text-blue-600 dark:text-blue-400" />
          <span className="text-sm font-semibold text-gray-800 dark:text-gray-100">
            QueryVault Security Demo
          </span>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-gray-100 dark:bg-gray-800">
            <span className="text-sm font-medium text-gray-900 dark:text-gray-100">
              {user.display_name}
            </span>
            <span className={`inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold ${badge.color}`}>
              {badge.label}
            </span>
            <span className="inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
              {user.domain}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={toggle}
            className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          >
            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
          <button
            onClick={logout}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-md transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Logout
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="max-w-5xl mx-auto px-6 py-8">
          {/* Role Info Banner */}
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-6">
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
              <div>
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">Department</span>
                <p className="font-medium text-gray-900 dark:text-gray-100">{user.department}</p>
              </div>
              <div>
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">Roles</span>
                <p className="font-medium text-gray-900 dark:text-gray-100">{user.ad_roles.join(', ')}</p>
              </div>
              <div>
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">Policies</span>
                <p className="font-medium text-gray-900 dark:text-gray-100">
                  {user.bound_policies.length > 0 ? user.bound_policies.join(', ') : 'None'}
                </p>
              </div>
              <div>
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">Clearance</span>
                <p className="font-medium text-gray-900 dark:text-gray-100">Level {user.clearance_level}</p>
              </div>
              <div>
                <span className="text-xs text-blue-600 dark:text-blue-400 font-medium">Status</span>
                <p className="font-medium text-gray-900 dark:text-gray-100">{user.employment_status}</p>
              </div>
            </div>
          </div>

          {/* Query Form */}
          <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 mb-6 shadow-sm">
            <form onSubmit={handleSubmit}>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Ask a question about hospital data
              </label>
              <textarea
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                required
                rows={3}
                placeholder="e.g., Show me all patients in the cardiology department..."
                className="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
              <div className="mt-3 flex items-center gap-3">
                <button
                  type="submit"
                  className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg disabled:opacity-50 transition-colors font-medium text-sm"
                  disabled={loading || !question.trim()}
                >
                  {loading ? (
                    <>
                      <LoadingSpinner size={16} /> Running...
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" /> Run Query
                    </>
                  )}
                </button>
                {loading && (
                  <span className="text-xs text-gray-500 dark:text-gray-400">
                    Processing through 5 security zones...
                  </span>
                )}
              </div>
            </form>
          </div>

          {/* Error */}
          {result?.error && (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
              <p className="text-sm text-red-700 dark:text-red-300">{result.error}</p>
            </div>
          )}

          {/* ══════════════════════════════════════════════════
              RESULTS — Full security detail panels
              ══════════════════════════════════════════════════ */}
          {data && (
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

              {/* ── Data Table ─────────────────────────────── */}
              {!data.blocked_reason && data.results && (
                <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-6 shadow-sm">
                  <h3 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
                    Query Results
                    {sec?.execution && (
                      <span className="ml-2 font-normal text-gray-500 dark:text-gray-400">
                        ({sec.execution.rows_returned} rows, {sec.execution.execution_latency_ms}ms)
                      </span>
                    )}
                  </h3>
                  <DataTable
                    data={
                      Array.isArray(data.results)
                        ? data.results
                        : Array.isArray(data.results?.rows)
                          ? data.results.rows
                          : null
                    }
                    emptyMessage="Query returned no rows."
                  />
                </div>
              )}

              {/* ── Raw Response JSON ──────────────────────── */}
              {result?.rawJson && (
                <CollapsibleSection title="Raw Response">
                  <JsonViewer rawJson={result.rawJson} />
                </CollapsibleSection>
              )}

              {/* ── Audit Footer ───────────────────────────── */}
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
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
