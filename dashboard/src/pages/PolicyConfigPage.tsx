import { useState, useEffect, useCallback } from 'react';
import {
  ArrowLeft, Shield, RefreshCw, Save, CheckCircle2, XCircle, Info, Filter,
  ChevronRight, Plus, X, Gauge, MessageSquare, User,
} from 'lucide-react';
import { useApiCall } from '../hooks/useApiCall';
import {
  listPolicyRoles, updatePolicyRole, syncPolicies,
  listMockUsers, generateMockToken, gatewayQuery,
} from '../api/queryvault';
import { PolicyRoleSummary, PolicyRolesResponse, RolePolicyUpdate } from '../types/policies';
import { GatewayQueryResponse } from '../types/queryvault';
import { MockUser, MockUsersResponse } from '../types/mockUsers';
import { generatePolicyStatements, PolicyStatement } from '../utils/policyStatements';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import { QueryResultView } from '../components/shared/QueryResultView';
import { useTheme } from '../hooks/useTheme';
import { Sun, Moon, LogOut } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import {
  CLEARANCE_BADGE,
  DOMAIN_GROUP_ORDER as _DOMAIN_ORDER,
  DOMAIN_GROUP_LABELS,
  DOMAIN_GROUP_COLORS,
} from '../constants/userCategories';

const ALL_TABLES = ['encounter_summaries', 'population_health', 'quality_metrics', 'research_cohorts'];
const ALL_OPS = ['DELETE', 'UPDATE', 'DROP', 'ALTER', 'TRUNCATE'];
const ALL_DOMAINS = ['CLINICAL', 'FINANCIAL', 'ADMINISTRATIVE', 'RESEARCH', 'COMPLIANCE', 'IT_OPERATIONS'];

// Extend shared order to include unconfigured bucket
const DOMAIN_GROUP_ORDER = [..._DOMAIN_ORDER, ''];

const CLEARANCE_COLORS: Record<number, string> = {
  1: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
  2: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  3: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  4: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  5: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
};

const STATEMENT_ICON: Record<string, { icon: typeof CheckCircle2; color: string }> = {
  allow: { icon: CheckCircle2, color: 'text-green-500' },
  deny: { icon: XCircle, color: 'text-red-500' },
  info: { icon: Info, color: 'text-blue-500' },
  filter: { icon: Filter, color: 'text-orange-500' },
};

interface PolicyConfigPageProps {
  onBack: () => void;
}

/* ── Statement Card with inline edit ─────────────────────── */

function StatementCard({
  statement,
  role,
  onSave,
}: {
  statement: PolicyStatement;
  role: PolicyRoleSummary;
  onSave: (update: RolePolicyUpdate) => Promise<void>;
}) {
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);

  const [allowedTables, setAllowedTables] = useState(role.allowed_tables);
  const [deniedTables, setDeniedTables] = useState(role.denied_tables);
  const [deniedOps, setDeniedOps] = useState(role.denied_operations);
  const [domains, setDomains] = useState(role.domains);
  const [resultLimit, setResultLimit] = useState<string>(role.result_limit != null ? String(role.result_limit) : '');
  const [rowFilters, setRowFilters] = useState<{ table: string; condition: string }[]>(
    role.row_filters.map(rf => typeof rf === 'string' ? { table: '', condition: rf } : rf as { table: string; condition: string })
  );

  useEffect(() => {
    setAllowedTables(role.allowed_tables);
    setDeniedTables(role.denied_tables);
    setDeniedOps(role.denied_operations);
    setDomains(role.domains);
    setResultLimit(role.result_limit != null ? String(role.result_limit) : '');
    setRowFilters(role.row_filters.map(rf => typeof rf === 'string' ? { table: '', condition: rf } : rf as { table: string; condition: string }));
  }, [role]);

  const toggle = (list: string[], item: string, setter: (v: string[]) => void) => {
    setter(list.includes(item) ? list.filter(i => i !== item) : [...list, item]);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave({
        allowed_tables: allowedTables,
        denied_tables: deniedTables,
        denied_operations: deniedOps,
        row_filters: rowFilters,
        domains,
        result_limit: resultLimit.trim() ? parseInt(resultLimit, 10) : null,
      });
      setEditing(false);
    } finally {
      setSaving(false);
    }
  };

  const { icon: Icon, color } = STATEMENT_ICON[statement.type] || STATEMENT_ICON.info;
  const isEditable = statement.section !== 'info' || statement.id === 'domains' || statement.id === 'result-limit';

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
      <div className="flex items-start gap-3 px-4 py-3">
        <Icon className={`w-5 h-5 mt-0.5 flex-shrink-0 ${color}`} />
        <p className="text-sm text-gray-800 dark:text-gray-200 flex-1 leading-relaxed">{statement.text}</p>
        {isEditable && !editing && (
          <button
            onClick={() => setEditing(true)}
            className="text-xs px-2.5 py-1 rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors flex-shrink-0"
          >
            Edit
          </button>
        )}
      </div>

      {editing && (
        <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-3 bg-gray-50 dark:bg-gray-800/50 space-y-3">
          {(statement.section === 'access' && statement.id === 'access') && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Allowed Tables</p>
              <div className="flex flex-wrap gap-2">
                {ALL_TABLES.map(t => (
                  <button key={t} onClick={() => toggle(allowedTables, t, setAllowedTables)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors cursor-pointer ${
                      allowedTables.includes(t)
                        ? 'bg-green-100 border-green-300 text-green-800 dark:bg-green-900/40 dark:border-green-700 dark:text-green-300'
                        : 'bg-gray-50 border-gray-200 text-gray-500 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-400'
                    }`}>{t}</button>
                ))}
              </div>
            </div>
          )}

          {(statement.section === 'access' && statement.id === 'denied-tables') && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Denied Tables</p>
              <div className="flex flex-wrap gap-2">
                {ALL_TABLES.map(t => (
                  <button key={t} onClick={() => toggle(deniedTables, t, setDeniedTables)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors cursor-pointer ${
                      deniedTables.includes(t)
                        ? 'bg-red-100 border-red-300 text-red-800 dark:bg-red-900/40 dark:border-red-700 dark:text-red-300'
                        : 'bg-gray-50 border-gray-200 text-gray-500 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-400'
                    }`}>{t}</button>
                ))}
              </div>
            </div>
          )}

          {statement.section === 'operations' && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Denied Operations</p>
              <div className="flex flex-wrap gap-2">
                {ALL_OPS.map(op => (
                  <button key={op} onClick={() => toggle(deniedOps, op, setDeniedOps)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors cursor-pointer ${
                      deniedOps.includes(op)
                        ? 'bg-orange-100 border-orange-300 text-orange-800 dark:bg-orange-900/40 dark:border-orange-700 dark:text-orange-300'
                        : 'bg-gray-50 border-gray-200 text-gray-500 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-400'
                    }`}>{op}</button>
                ))}
              </div>
            </div>
          )}

          {statement.id === 'domains' && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Access Domains</p>
              <div className="flex flex-wrap gap-2">
                {ALL_DOMAINS.map(d => (
                  <button key={d} onClick={() => toggle(domains, d, setDomains)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors cursor-pointer ${
                      domains.includes(d)
                        ? 'bg-purple-100 border-purple-300 text-purple-800 dark:bg-purple-900/40 dark:border-purple-700 dark:text-purple-300'
                        : 'bg-gray-50 border-gray-200 text-gray-500 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-400'
                    }`}>{d}</button>
                ))}
              </div>
            </div>
          )}

          {statement.id === 'result-limit' && (
            <div>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-2">Maximum rows per query</p>
              <div className="flex items-center gap-2">
                <input type="number" min="1" max="10000" value={resultLimit}
                  onChange={e => setResultLimit(e.target.value)}
                  className="w-32 text-sm px-3 py-1.5 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
                  placeholder="e.g. 50" />
                <span className="text-xs text-gray-400">rows</span>
                <button onClick={() => setResultLimit('')}
                  className="text-xs text-red-500 hover:text-red-700 dark:hover:text-red-400 ml-2">
                  Remove limit
                </button>
              </div>
            </div>
          )}

          {statement.section === 'filters' && (
            <div className="space-y-2">
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400">Row Filters</p>
              {rowFilters.map((rf, i) => (
                <div key={i} className="flex items-center gap-2">
                  <select value={rf.table}
                    onChange={e => { const c = [...rowFilters]; c[i] = { ...c[i], table: e.target.value }; setRowFilters(c); }}
                    className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200">
                    {ALL_TABLES.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                  <input value={rf.condition}
                    onChange={e => { const c = [...rowFilters]; c[i] = { ...c[i], condition: e.target.value }; setRowFilters(c); }}
                    className="flex-1 text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
                    placeholder="e.g. facility_id = '{{user.facility}}'" />
                  <button onClick={() => setRowFilters(rowFilters.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-600">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
              <button onClick={() => setRowFilters([...rowFilters, { table: ALL_TABLES[0], condition: '' }])}
                className="text-xs text-blue-600 dark:text-blue-400 hover:underline">+ Add filter</button>
            </div>
          )}

          <div className="flex items-center gap-2 pt-1">
            <button onClick={handleSave} disabled={saving}
              className="flex items-center gap-1 text-xs px-3 py-1.5 rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 transition-colors">
              {saving ? <LoadingSpinner size={12} /> : <Save className="w-3 h-3" />} Save to Neo4j
            </button>
            <button onClick={() => { setEditing(false); setAllowedTables(role.allowed_tables); setDeniedTables(role.denied_tables); setDeniedOps(role.denied_operations); setDomains(role.domains); setResultLimit(role.result_limit != null ? String(role.result_limit) : ''); }}
              className="text-xs px-3 py-1.5 rounded bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

/* ── Policy Type Cards for Add Form ────────────────────────── */

const POLICY_TYPES = [
  { id: 'access' as const, label: 'Grant Table Access', description: 'Allow this role to query a specific table', icon: CheckCircle2, color: 'green' },
  { id: 'denied-table' as const, label: 'Deny Table Access', description: 'Block this role from accessing a specific table', icon: XCircle, color: 'red' },
  { id: 'operation' as const, label: 'Restrict Operation', description: 'Prevent SQL operations (DELETE, DROP, etc.)', icon: XCircle, color: 'orange' },
  { id: 'domain' as const, label: 'Assign Domain', description: 'Grant access to a data domain', icon: Info, color: 'purple' },
  { id: 'filter' as const, label: 'Add Row Filter', description: 'Restrict rows by condition', icon: Filter, color: 'amber' },
  { id: 'result-limit' as const, label: 'Set Result Limit', description: 'Limit max rows per query', icon: Gauge, color: 'cyan' },
];

const COLOR_MAP: Record<string, { bg: string; border: string; text: string; ring: string }> = {
  green:  { bg: 'bg-green-50 dark:bg-green-900/20', border: 'border-green-200 dark:border-green-800', text: 'text-green-700 dark:text-green-400', ring: 'ring-green-400' },
  red:    { bg: 'bg-red-50 dark:bg-red-900/20', border: 'border-red-200 dark:border-red-800', text: 'text-red-700 dark:text-red-400', ring: 'ring-red-400' },
  orange: { bg: 'bg-orange-50 dark:bg-orange-900/20', border: 'border-orange-200 dark:border-orange-800', text: 'text-orange-700 dark:text-orange-400', ring: 'ring-orange-400' },
  purple: { bg: 'bg-purple-50 dark:bg-purple-900/20', border: 'border-purple-200 dark:border-purple-800', text: 'text-purple-700 dark:text-purple-400', ring: 'ring-purple-400' },
  amber:  { bg: 'bg-amber-50 dark:bg-amber-900/20', border: 'border-amber-200 dark:border-amber-800', text: 'text-amber-700 dark:text-amber-400', ring: 'ring-amber-400' },
  cyan:   { bg: 'bg-cyan-50 dark:bg-cyan-900/20', border: 'border-cyan-200 dark:border-cyan-800', text: 'text-cyan-700 dark:text-cyan-400', ring: 'ring-cyan-400' },
};

/* ── Add Policy Form ─────────────────────────────────────── */

function AddPolicyForm({ role, onSave }: { role: PolicyRoleSummary; onSave: (update: RolePolicyUpdate) => Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [step, setStep] = useState<1 | 2>(1);
  const [policyType, setPolicyType] = useState<'access' | 'denied-table' | 'operation' | 'domain' | 'filter' | 'result-limit'>('access');
  const [selectedTables, setSelectedTables] = useState<string[]>([]);
  const [selectedOps, setSelectedOps] = useState<string[]>([]);
  const [selectedDomains, setSelectedDomains] = useState<string[]>([]);
  const [filterTable, setFilterTable] = useState(ALL_TABLES[0]);
  const [filterCondition, setFilterCondition] = useState('');
  const [limitValue, setLimitValue] = useState('');
  const [saving, setSaving] = useState(false);

  const resetForm = () => {
    setStep(1); setSelectedTables([]); setSelectedOps([]); setSelectedDomains([]);
    setFilterTable(ALL_TABLES[0]); setFilterCondition(''); setLimitValue('');
  };

  const toggleItem = (list: string[], item: string, setter: (v: string[]) => void) => {
    setter(list.includes(item) ? list.filter(i => i !== item) : [...list, item]);
  };

  const getPreview = (): string => {
    switch (policyType) {
      case 'access': return selectedTables.length > 0 ? `This role can query ${selectedTables.join(', ')}` : 'Select tables below';
      case 'denied-table': return selectedTables.length > 0 ? `This role is denied access to ${selectedTables.join(', ')}` : 'Select tables below';
      case 'operation': return selectedOps.length > 0 ? `This role cannot perform ${selectedOps.join(', ')} operations` : 'Select operations below';
      case 'domain': return selectedDomains.length > 0 ? `This role operates within ${selectedDomains.join(', ')}` : 'Select domains below';
      case 'filter': return filterCondition ? `Row filter on ${filterTable}: only rows where ${filterCondition}` : `Row filter on ${filterTable}: (enter condition)`;
      case 'result-limit': return limitValue.trim() ? `Query results limited to ${limitValue} rows` : 'Enter a row limit below';
    }
  };

  const canSave = (): boolean => {
    switch (policyType) {
      case 'access': case 'denied-table': return selectedTables.length > 0;
      case 'operation': return selectedOps.length > 0;
      case 'domain': return selectedDomains.length > 0;
      case 'filter': return filterCondition.trim().length > 0;
      case 'result-limit': return limitValue.trim().length > 0 && parseInt(limitValue, 10) > 0;
    }
  };

  const handleAdd = async () => {
    setSaving(true);
    const update: RolePolicyUpdate = {
      allowed_tables: [...role.allowed_tables],
      denied_tables: [...role.denied_tables],
      denied_operations: [...role.denied_operations],
      row_filters: role.row_filters.map(rf => typeof rf === 'string' ? { table: '', condition: rf } : rf as { table: string; condition: string }),
      domains: [...role.domains],
    };
    switch (policyType) {
      case 'access': selectedTables.forEach(t => { if (!update.allowed_tables.includes(t)) update.allowed_tables.push(t); }); break;
      case 'denied-table': selectedTables.forEach(t => { if (!update.denied_tables.includes(t)) update.denied_tables.push(t); }); break;
      case 'operation': selectedOps.forEach(op => { if (!update.denied_operations.includes(op)) update.denied_operations.push(op); }); break;
      case 'domain': selectedDomains.forEach(d => { if (!update.domains.includes(d)) update.domains.push(d); }); break;
      case 'filter': update.row_filters.push({ table: filterTable, condition: filterCondition }); break;
      case 'result-limit': update.result_limit = parseInt(limitValue, 10); break;
    }
    try { await onSave(update); setOpen(false); resetForm(); } finally { setSaving(false); }
  };

  if (!open) {
    return (
      <button onClick={() => { setOpen(true); resetForm(); }}
        className="flex items-center gap-2 text-sm font-medium text-blue-600 dark:text-blue-400 hover:text-blue-700 dark:hover:text-blue-300 transition-colors py-2">
        <Plus className="w-4 h-4" /> Add New Policy Statement
      </button>
    );
  }

  const activePT = POLICY_TYPES.find(p => p.id === policyType)!;
  const colors = COLOR_MAP[activePT.color];

  return (
    <div className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-xl overflow-hidden shadow-sm">
      <div className="flex items-center justify-between px-5 py-3 border-b border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800/50">
        <div className="flex items-center gap-2">
          <Plus className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-200">
            {step === 1 ? 'Step 1: Choose Policy Type' : 'Step 2: Configure Details'}
          </h4>
        </div>
        <button onClick={() => { setOpen(false); resetForm(); }} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-5 space-y-4">
        {step === 1 && (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {POLICY_TYPES.map(pt => {
                const isSelected = policyType === pt.id;
                const c = COLOR_MAP[pt.color];
                const PTIcon = pt.icon;
                return (
                  <button key={pt.id} onClick={() => setPolicyType(pt.id)}
                    className={`text-left rounded-lg border-2 p-4 transition-all ${
                      isSelected ? `${c.bg} ${c.border} ring-2 ${c.ring}` : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                    }`}>
                    <div className="flex items-center gap-2 mb-1">
                      <PTIcon className={`w-4 h-4 ${isSelected ? c.text : 'text-gray-400'}`} />
                      <span className={`text-sm font-semibold ${isSelected ? c.text : 'text-gray-700 dark:text-gray-300'}`}>{pt.label}</span>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 leading-relaxed">{pt.description}</p>
                  </button>
                );
              })}
            </div>
            <div className="flex justify-end">
              <button onClick={() => setStep(2)}
                className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-blue-600 text-white hover:bg-blue-700 transition-colors font-medium">
                Next <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </>
        )}

        {step === 2 && (
          <>
            <button onClick={() => setStep(1)} className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-blue-600 transition-colors">
              <ArrowLeft className="w-3 h-3" /> Change policy type
            </button>

            {/* Live Preview */}
            <div className={`rounded-lg border p-4 ${colors.bg} ${colors.border}`}>
              <p className="text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-1">Policy Preview</p>
              <div className="flex items-start gap-2">
                <activePT.icon className={`w-5 h-5 mt-0.5 ${colors.text}`} />
                <p className={`text-sm font-medium ${colors.text} leading-relaxed`}>{getPreview()}</p>
              </div>
            </div>

            {/* Table Selection */}
            {(policyType === 'access' || policyType === 'denied-table') && (
              <div>
                <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">
                  {policyType === 'access' ? 'Select tables to allow' : 'Select tables to deny'}
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {ALL_TABLES.map(t => {
                    const isActive = selectedTables.includes(t);
                    const already = policyType === 'access' ? role.allowed_tables.includes(t) : role.denied_tables.includes(t);
                    return (
                      <button key={t} onClick={() => toggleItem(selectedTables, t, setSelectedTables)} disabled={already}
                        className={`text-left text-sm px-3 py-2.5 rounded-lg border-2 transition-all ${
                          already ? 'border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50 text-gray-400 cursor-not-allowed'
                          : isActive ? `${colors.bg} ${colors.border} ${colors.text} font-medium`
                          : 'border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-gray-300 cursor-pointer'
                        }`}>
                        <span className="font-mono text-xs">{t}</span>
                        {already && <span className="block text-[10px] text-gray-400 mt-0.5">Already {policyType === 'access' ? 'allowed' : 'denied'}</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Operation Selection */}
            {policyType === 'operation' && (
              <div>
                <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">Select operations to deny</label>
                <div className="flex flex-wrap gap-2">
                  {ALL_OPS.map(op => {
                    const isActive = selectedOps.includes(op);
                    const already = role.denied_operations.includes(op);
                    return (
                      <button key={op} onClick={() => toggleItem(selectedOps, op, setSelectedOps)} disabled={already}
                        className={`text-sm px-4 py-2 rounded-lg border-2 transition-all ${
                          already ? 'border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50 text-gray-400 cursor-not-allowed'
                          : isActive ? `${colors.bg} ${colors.border} ${colors.text} font-medium`
                          : 'border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-gray-300 cursor-pointer'
                        }`}>
                        {op}
                        {already && <span className="block text-[10px] text-gray-400">Already denied</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Domain Selection */}
            {policyType === 'domain' && (
              <div>
                <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">Select domains to grant</label>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                  {ALL_DOMAINS.map(d => {
                    const isActive = selectedDomains.includes(d);
                    const already = role.domains.includes(d);
                    return (
                      <button key={d} onClick={() => toggleItem(selectedDomains, d, setSelectedDomains)} disabled={already}
                        className={`text-sm px-3 py-2.5 rounded-lg border-2 transition-all text-left ${
                          already ? 'border-gray-100 dark:border-gray-800 bg-gray-50 dark:bg-gray-800/50 text-gray-400 cursor-not-allowed'
                          : isActive ? `${colors.bg} ${colors.border} ${colors.text} font-medium`
                          : 'border-gray-200 dark:border-gray-700 text-gray-700 dark:text-gray-300 hover:border-gray-300 cursor-pointer'
                        }`}>
                        {d}
                        {already && <span className="block text-[10px] text-gray-400">Already assigned</span>}
                      </button>
                    );
                  })}
                </div>
              </div>
            )}

            {/* Row Filter */}
            {policyType === 'filter' && (
              <div className="space-y-3">
                <div>
                  <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">Table</label>
                  <select value={filterTable} onChange={e => setFilterTable(e.target.value)}
                    className="w-full text-sm px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200">
                    {ALL_TABLES.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">WHERE condition</label>
                  <input value={filterCondition} onChange={e => setFilterCondition(e.target.value)}
                    placeholder="e.g. facility_id = '{{user.facility}}'"
                    className="w-full text-sm px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 placeholder-gray-400" />
                </div>
              </div>
            )}

            {/* Result Limit */}
            {policyType === 'result-limit' && (
              <div>
                <label className="block text-xs font-semibold text-gray-600 dark:text-gray-400 uppercase tracking-wider mb-2">Maximum rows per query</label>
                <div className="flex items-center gap-3">
                  <input type="number" min="1" max="10000" value={limitValue} onChange={e => setLimitValue(e.target.value)}
                    placeholder="e.g. 50"
                    className="w-40 text-sm px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200 placeholder-gray-400" />
                  <span className="text-sm text-gray-500 dark:text-gray-400">rows</span>
                </div>
                {role.result_limit != null && (
                  <p className="text-[10px] text-amber-600 dark:text-amber-400 mt-2">Current limit: {role.result_limit} rows — saving will override it</p>
                )}
              </div>
            )}

            {/* Save */}
            <div className="flex items-center gap-3 pt-2 border-t border-gray-200 dark:border-gray-700">
              <button onClick={handleAdd} disabled={saving || !canSave()}
                className="flex items-center gap-1.5 text-sm px-5 py-2.5 rounded-lg bg-blue-600 text-white hover:bg-blue-700 disabled:opacity-50 transition-colors font-medium">
                {saving ? <LoadingSpinner size={14} /> : <Save className="w-4 h-4" />} Save Policy to Neo4j
              </button>
              <button onClick={() => { setOpen(false); resetForm(); }}
                className="text-sm px-4 py-2.5 rounded-lg bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 transition-colors">
                Cancel
              </button>
              {!canSave() && <span className="text-xs text-gray-400">{policyType === 'filter' ? 'Enter a WHERE condition' : policyType === 'result-limit' ? 'Enter a row limit' : 'Select at least one item'}</span>}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

/* ── Role Query Section ─────────────────────────────────────── */

function RoleQuerySection({ roleName, mockUsers }: { roleName: string; mockUsers: MockUser[] }) {
  const { loading, result, execute } = useApiCall<GatewayQueryResponse>();
  const [question, setQuestion] = useState('');
  const [jwtToken, setJwtToken] = useState('');
  const [selectedUser, setSelectedUser] = useState<MockUser | null>(null);
  const [generatingToken, setGeneratingToken] = useState(false);

  // Find mock users that have this role
  const matchingUsers = mockUsers.filter(u => u.ad_roles.includes(roleName));

  // Auto-generate token for the first matching user
  useEffect(() => {
    setJwtToken('');
    setSelectedUser(null);
    setQuestion('');
    if (matchingUsers.length > 0) {
      selectUser(matchingUsers[0]);
    }
  }, [roleName]);

  const selectUser = async (user: MockUser) => {
    setGeneratingToken(true);
    try {
      const res = await generateMockToken(user.oid);
      if (res.data) {
        setJwtToken(res.data.jwt_token);
        setSelectedUser(user);
      }
    } finally {
      setGeneratingToken(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!jwtToken.trim() || !question.trim()) return;
    execute(() => gatewayQuery({ question, jwt_token: jwtToken }));
  };

  const data = result?.data;

  return (
    <div className="space-y-4">
      {/* User Context */}
      {matchingUsers.length === 0 ? (
        <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
          <p className="text-sm text-yellow-700 dark:text-yellow-300">
            No test users found with role <span className="font-mono font-semibold">{roleName}</span>. Configure a mock user with this role to test queries.
          </p>
        </div>
      ) : (
        <div>
          {/* User selector if multiple users */}
          {matchingUsers.length > 1 && (
            <div className="mb-3">
              <p className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Select Test User</p>
              <div className="flex flex-wrap gap-2">
                {matchingUsers.map(u => (
                  <button key={u.oid} onClick={() => selectUser(u)}
                    className={`text-xs px-3 py-1.5 rounded-lg border transition-all ${
                      selectedUser?.oid === u.oid
                        ? 'bg-blue-50 dark:bg-blue-900/30 border-blue-300 dark:border-blue-700 text-blue-700 dark:text-blue-300 font-medium'
                        : 'border-gray-200 dark:border-gray-700 text-gray-600 dark:text-gray-400 hover:border-gray-300 cursor-pointer'
                    }`}>
                    {u.display_name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Selected user badge */}
          {selectedUser && (
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <User className="w-4 h-4 text-blue-500" />
                <span className="font-medium text-gray-900 dark:text-gray-100">{selectedUser.display_name}</span>
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${CLEARANCE_COLORS[selectedUser.clearance_level] || CLEARANCE_COLORS[1]}`}>
                  L{selectedUser.clearance_level}
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 font-medium">
                  {selectedUser.domain}
                </span>
                <span className="text-xs text-gray-500 dark:text-gray-400">
                  {selectedUser.department}
                </span>
              </div>
            </div>
          )}

          {generatingToken && (
            <div className="flex items-center gap-2 text-sm text-gray-500 dark:text-gray-400">
              <LoadingSpinner size={14} /> Generating JWT token...
            </div>
          )}
        </div>
      )}

      {/* Query Form */}
      {jwtToken && (
        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <textarea value={question} onChange={e => setQuestion(e.target.value)} required rows={3}
              placeholder="Ask a question about the data..."
              className="w-full px-4 py-3 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm" />
          </div>
          <button type="submit" disabled={loading || !question.trim()}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-lg disabled:opacity-50 text-sm font-medium transition-colors">
            {loading ? <><LoadingSpinner size={14} /> Querying...</> : <><MessageSquare className="w-4 h-4" /> Submit Query</>}
          </button>
        </form>
      )}

      {/* Error */}
      {result?.error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
          <p className="text-sm text-red-700 dark:text-red-300">{result.error}</p>
        </div>
      )}

      {/* Results */}
      {data && <QueryResultView data={data} rawJson={result.rawJson} />}
    </div>
  );
}

/* ── Main Page ───────────────────────────────────────────── */

export function PolicyConfigPage({ onBack }: PolicyConfigPageProps) {
  const { loading, result, execute } = useApiCall<PolicyRolesResponse>();
  const { result: mockUsersResult, execute: fetchMockUsers } = useApiCall<MockUsersResponse>();
  const [selectedRole, setSelectedRole] = useState<string | null>(null);
  const [filter, setFilter] = useState('');
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');
  const { auth, logout } = useAuth();
  const { isDark, toggle: toggleTheme } = useTheme();

  const load = useCallback(() => execute(() => listPolicyRoles()), [execute]);
  useEffect(() => { load(); fetchMockUsers(() => listMockUsers()); }, [load]);

  const roles = result?.data?.roles ?? [];
  const mockUsers = mockUsersResult?.data?.users ?? [];
  const filteredRoles = filter
    ? roles.filter(r => r.name.toLowerCase().includes(filter.toLowerCase()) || r.domain.toLowerCase().includes(filter.toLowerCase()))
    : roles;

  const grouped = DOMAIN_GROUP_ORDER.reduce<Record<string, PolicyRoleSummary[]>>((acc, domain) => {
    const matching = filteredRoles.filter(r => r.domain === domain);
    if (matching.length > 0) acc[domain] = matching;
    return acc;
  }, {});

  const selected = roles.find(r => r.name === selectedRole) || null;
  const statements = selected ? generatePolicyStatements(selected) : [];

  const handleSave = async (update: RolePolicyUpdate) => {
    if (!selectedRole) return;
    await updatePolicyRole(selectedRole, update);
    load();
  };

  const handleSync = async () => {
    setSyncing(true);
    setSyncMsg('');
    try {
      const res = await syncPolicies();
      setSyncMsg(res.data ? 'Synced successfully' : (res.error || 'Sync failed'));
      load();
    } finally {
      setSyncing(false);
      setTimeout(() => setSyncMsg(''), 4000);
    }
  };

  const userBadge = auth ? CLEARANCE_BADGE[auth.user.clearance_level] || CLEARANCE_BADGE[1] : null;

  return (
    <div className="h-screen flex flex-col bg-gray-50 dark:bg-gray-950">
      {/* Top Bar */}
      <header className="h-14 border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 flex items-center justify-between px-5 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button onClick={selected ? () => setSelectedRole(null) : onBack}
            className="flex items-center gap-1.5 text-sm text-gray-600 dark:text-gray-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
            <ArrowLeft className="w-4 h-4" /> {selected ? 'Back to Roles' : 'Back to Dashboard'}
          </button>
          <div className="h-5 w-px bg-gray-200 dark:bg-gray-700" />
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-blue-600 dark:text-blue-400" />
            <span className="text-sm font-semibold text-gray-800 dark:text-gray-100">
              {selected ? selected.name.replace(/_/g, ' ') : 'Policy Configuration'}
            </span>
            {selected && (
              <>
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${CLEARANCE_COLORS[selected.clearance_level] || CLEARANCE_COLORS[1]}`}>
                  L{selected.clearance_level}
                </span>
                {selected.domain && (
                  <span className="text-[10px] font-medium px-1.5 py-0.5 rounded-full bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">
                    {selected.domain}
                  </span>
                )}
              </>
            )}
          </div>
        </div>

        <div className="flex items-center gap-3">
          {syncMsg && <span className="text-xs text-green-600 dark:text-green-400">{syncMsg}</span>}
          {!selected && (
            <button onClick={handleSync} disabled={syncing}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50 transition-colors">
              {syncing ? <LoadingSpinner size={12} /> : <RefreshCw className="w-3 h-3" />} Sync to Neo4j
            </button>
          )}
          {auth && (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-gray-100 dark:bg-gray-800">
              <span className="text-xs font-medium text-gray-700 dark:text-gray-300">{auth.user.display_name}</span>
              {userBadge && <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${userBadge.color}`}>{userBadge.label}</span>}
            </div>
          )}
          <button onClick={toggleTheme} className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors">
            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
          <button onClick={logout} className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors">
            <LogOut className="w-3.5 h-3.5" /> Logout
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 overflow-y-auto">
        {!selected ? (
          /* ═══════════════════════════════════════════════
             VIEW 1: Role Grid (no role selected)
             ═══════════════════════════════════════════════ */
          <div className="max-w-6xl mx-auto p-6">
            {/* Search */}
            <div className="mb-6">
              <input type="text" value={filter} onChange={e => setFilter(e.target.value)}
                placeholder="Search roles by name or domain..."
                className="w-full max-w-md text-sm px-4 py-2.5 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>

            {loading && <div className="flex justify-center py-12"><LoadingSpinner size={24} /></div>}

            {!loading && Object.entries(grouped).map(([domain, domainRoles]) => (
              <div key={domain} className="mb-8">
                <h3 className="text-xs font-bold uppercase tracking-wider text-gray-500 dark:text-gray-400 mb-3 flex items-center gap-2">
                  <div className={`w-2 h-2 rounded-full ${
                    domain === 'CLINICAL' ? 'bg-blue-500' :
                    domain === 'FINANCIAL' ? 'bg-emerald-500' :
                    domain === 'ADMINISTRATIVE' ? 'bg-purple-500' :
                    domain === 'RESEARCH' ? 'bg-indigo-500' :
                    domain === 'COMPLIANCE' ? 'bg-teal-500' :
                    domain === 'IT_OPERATIONS' ? 'bg-orange-500' : 'bg-gray-400'
                  }`} />
                  {DOMAIN_GROUP_LABELS[domain] || domain}
                  <span className="text-[10px] font-normal text-gray-400">({domainRoles.length})</span>
                </h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                  {domainRoles.map(role => {
                    const stmtCount = generatePolicyStatements(role).length;
                    const clBadge = CLEARANCE_COLORS[role.clearance_level] || CLEARANCE_COLORS[1];
                    const borderColor = DOMAIN_GROUP_COLORS[domain] || DOMAIN_GROUP_COLORS[''];
                    return (
                      <button key={role.name} onClick={() => setSelectedRole(role.name)}
                        className={`text-left bg-white dark:bg-gray-900 rounded-xl border-2 ${borderColor} p-4 hover:shadow-md hover:scale-[1.02] transition-all cursor-pointer group`}>
                        <div className="flex items-center gap-2 mb-2">
                          <Shield className="w-4 h-4 text-gray-400 group-hover:text-blue-500 transition-colors" />
                          <h4 className="text-sm font-semibold text-gray-800 dark:text-gray-100 truncate group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                            {role.name.replace(/_/g, ' ')}
                          </h4>
                        </div>
                        <div className="flex items-center gap-2 mb-2">
                          <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${clBadge}`}>L{role.clearance_level}</span>
                          <span className="text-[10px] text-gray-400 dark:text-gray-500">{stmtCount} policies</span>
                        </div>
                        {role.bound_policies.length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            {role.bound_policies.map(p => (
                              <span key={p} className="text-[9px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400">{p}</span>
                            ))}
                          </div>
                        )}
                        <div className="mt-2 flex items-center gap-1 text-[10px] text-blue-500 dark:text-blue-400 opacity-0 group-hover:opacity-100 transition-opacity">
                          <ChevronRight className="w-3 h-3" /> View & Configure
                        </div>
                      </button>
                    );
                  })}
                </div>
              </div>
            ))}

            {!loading && Object.keys(grouped).length === 0 && (
              <div className="text-center py-12 text-gray-400 dark:text-gray-500">
                <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No roles found</p>
              </div>
            )}
          </div>
        ) : (
          /* ═══════════════════════════════════════════════
             VIEW 2: Role Detail (role selected, full page)
             ═══════════════════════════════════════════════ */
          <div className="max-w-4xl mx-auto p-6 space-y-8">
            {/* Role Header */}
            <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5">
              <div className="flex items-center gap-3 mb-3">
                <Shield className="w-6 h-6 text-blue-600 dark:text-blue-400" />
                <h2 className="text-xl font-bold text-gray-800 dark:text-gray-100">{selected.name.replace(/_/g, ' ')}</h2>
                <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${CLEARANCE_COLORS[selected.clearance_level] || CLEARANCE_COLORS[1]}`}>
                  Level {selected.clearance_level}
                </span>
                {selected.domain && (
                  <span className="text-xs font-medium px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">
                    {selected.domain}
                  </span>
                )}
              </div>
              {selected.bound_policies.length > 0 && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500 dark:text-gray-400">Bound Policies:</span>
                  {selected.bound_policies.map(p => (
                    <span key={p} className="text-xs px-2 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">{p}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Policy Statements */}
            <div>
              <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3">
                Policy Statements ({statements.length})
              </h3>
              <div className="space-y-2">
                {statements.map(stmt => (
                  <StatementCard key={stmt.id} statement={stmt} role={selected} onSave={handleSave} />
                ))}
              </div>
              <div className="mt-4">
                <AddPolicyForm role={selected} onSave={handleSave} />
              </div>
            </div>

            {/* Query Section */}
            <div>
              <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
                <MessageSquare className="w-3.5 h-3.5" />
                Test Query as This Role
              </h3>
              <div className="bg-white dark:bg-gray-900 rounded-xl border border-gray-200 dark:border-gray-800 p-5">
                <RoleQuerySection roleName={selected.name} mockUsers={mockUsers} />
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
