import { useState, useEffect, useCallback } from 'react';
import { Shield, ChevronDown, ChevronRight, Save, RefreshCw, X, Check } from 'lucide-react';
import { useApiCall } from '../../hooks/useApiCall';
import { listPolicyRoles, updatePolicyRole, syncPolicies } from '../../api/queryvault';
import { PolicyRoleSummary, PolicyRolesResponse, RolePolicyUpdate } from '../../types/policies';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const ALL_TABLES = ['encounter_summaries', 'population_health', 'quality_metrics', 'research_cohorts'];
const ALL_OPS = ['DELETE', 'UPDATE', 'DROP', 'ALTER', 'TRUNCATE'];
const ALL_DOMAINS = ['CLINICAL', 'FINANCIAL', 'ADMINISTRATIVE', 'RESEARCH', 'COMPLIANCE', 'IT_OPERATIONS'];

const CLEARANCE_COLORS: Record<number, string> = {
  1: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300',
  2: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  3: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  4: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  5: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
};

function RoleCard({ role, onSave }: { role: PolicyRoleSummary; onSave: (name: string, update: RolePolicyUpdate) => Promise<void> }) {
  const [expanded, setExpanded] = useState(false);
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  const [allowedTables, setAllowedTables] = useState<string[]>(role.allowed_tables);
  const [deniedTables, setDeniedTables] = useState<string[]>(role.denied_tables);
  const [deniedOps, setDeniedOps] = useState<string[]>(role.denied_operations);
  const [domains, setDomains] = useState<string[]>(role.domains);
  const [rowFilters, setRowFilters] = useState<{ table: string; condition: string }[]>(
    role.row_filters.map(rf => {
      if (typeof rf === 'string') {
        const parts = rf.split(': ');
        return { table: parts[0] || '', condition: parts[1] || rf };
      }
      return rf as { table: string; condition: string };
    })
  );

  useEffect(() => {
    setAllowedTables(role.allowed_tables);
    setDeniedTables(role.denied_tables);
    setDeniedOps(role.denied_operations);
    setDomains(role.domains);
    setRowFilters(
      role.row_filters.map(rf => {
        if (typeof rf === 'string') {
          const parts = rf.split(': ');
          return { table: parts[0] || '', condition: parts[1] || rf };
        }
        return rf as { table: string; condition: string };
      })
    );
  }, [role]);

  const toggleItem = (list: string[], item: string, setter: (v: string[]) => void) => {
    setter(list.includes(item) ? list.filter(i => i !== item) : [...list, item]);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await onSave(role.name, { allowed_tables: allowedTables, denied_tables: deniedTables, denied_operations: deniedOps, row_filters: rowFilters, domains });
      setSaved(true);
      setEditing(false);
      setTimeout(() => setSaved(false), 2000);
    } finally {
      setSaving(false);
    }
  };

  const clearanceBadge = CLEARANCE_COLORS[role.clearance_level] || CLEARANCE_COLORS[1];

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-800/50 transition-colors text-left"
      >
        {expanded ? <ChevronDown className="w-4 h-4 text-gray-400" /> : <ChevronRight className="w-4 h-4 text-gray-400" />}
        <Shield className="w-4 h-4 text-blue-500" />
        <span className="text-sm font-semibold text-gray-800 dark:text-gray-200 flex-1">{role.name}</span>
        <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${clearanceBadge}`}>
          L{role.clearance_level}
        </span>
        {role.domain && (
          <span className="text-[10px] font-medium px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 dark:bg-purple-900 dark:text-purple-300">
            {role.domain}
          </span>
        )}
        <span className="text-[10px] text-gray-500 dark:text-gray-400">
          {role.allowed_tables.length} tables
        </span>
        {saved && <Check className="w-4 h-4 text-green-500" />}
      </button>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-gray-200 dark:border-gray-700 px-4 py-4 space-y-4">
          {/* Toolbar */}
          <div className="flex items-center gap-2">
            {!editing ? (
              <button
                onClick={() => setEditing(true)}
                className="text-xs px-3 py-1.5 rounded bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors"
              >
                Edit Policies
              </button>
            ) : (
              <>
                <button
                  onClick={handleSave}
                  disabled={saving}
                  className="flex items-center gap-1 text-xs px-3 py-1.5 rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
                >
                  {saving ? <LoadingSpinner size={12} /> : <Save className="w-3 h-3" />} Save
                </button>
                <button
                  onClick={() => { setEditing(false); setAllowedTables(role.allowed_tables); setDeniedTables(role.denied_tables); setDeniedOps(role.denied_operations); setDomains(role.domains); }}
                  className="text-xs px-3 py-1.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                >
                  Cancel
                </button>
              </>
            )}
            {role.bound_policies.length > 0 && (
              <div className="ml-auto flex gap-1">
                {role.bound_policies.map(p => (
                  <span key={p} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-500 dark:text-gray-400">{p}</span>
                ))}
              </div>
            )}
          </div>

          {/* Allowed Tables */}
          <div>
            <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Allowed Tables</h4>
            <div className="flex flex-wrap gap-2">
              {ALL_TABLES.map(t => {
                const active = allowedTables.includes(t);
                return (
                  <button
                    key={t}
                    disabled={!editing}
                    onClick={() => toggleItem(allowedTables, t, setAllowedTables)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      active
                        ? 'bg-green-100 border-green-300 text-green-800 dark:bg-green-900/40 dark:border-green-700 dark:text-green-300'
                        : 'bg-gray-50 border-gray-200 text-gray-400 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-500'
                    } ${editing ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
                  >
                    {t}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Denied Tables */}
          <div>
            <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Denied Tables</h4>
            <div className="flex flex-wrap gap-2">
              {ALL_TABLES.map(t => {
                const active = deniedTables.includes(t);
                return (
                  <button
                    key={t}
                    disabled={!editing}
                    onClick={() => toggleItem(deniedTables, t, setDeniedTables)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      active
                        ? 'bg-red-100 border-red-300 text-red-800 dark:bg-red-900/40 dark:border-red-700 dark:text-red-300'
                        : 'bg-gray-50 border-gray-200 text-gray-400 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-500'
                    } ${editing ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
                  >
                    {t}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Denied Operations */}
          <div>
            <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Denied Operations</h4>
            <div className="flex flex-wrap gap-2">
              {ALL_OPS.map(op => {
                const active = deniedOps.includes(op);
                return (
                  <button
                    key={op}
                    disabled={!editing}
                    onClick={() => toggleItem(deniedOps, op, setDeniedOps)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      active
                        ? 'bg-orange-100 border-orange-300 text-orange-800 dark:bg-orange-900/40 dark:border-orange-700 dark:text-orange-300'
                        : 'bg-gray-50 border-gray-200 text-gray-400 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-500'
                    } ${editing ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
                  >
                    {op}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Domains */}
          <div>
            <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Access Domains</h4>
            <div className="flex flex-wrap gap-2">
              {ALL_DOMAINS.map(d => {
                const active = domains.includes(d);
                return (
                  <button
                    key={d}
                    disabled={!editing}
                    onClick={() => toggleItem(domains, d, setDomains)}
                    className={`text-xs px-2.5 py-1 rounded-full border transition-colors ${
                      active
                        ? 'bg-purple-100 border-purple-300 text-purple-800 dark:bg-purple-900/40 dark:border-purple-700 dark:text-purple-300'
                        : 'bg-gray-50 border-gray-200 text-gray-400 dark:bg-gray-800 dark:border-gray-700 dark:text-gray-500'
                    } ${editing ? 'cursor-pointer hover:opacity-80' : 'cursor-default'}`}
                  >
                    {d}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Row Filters */}
          {(rowFilters.length > 0 || editing) && (
            <div>
              <h4 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2">Row Filters</h4>
              {rowFilters.length === 0 && !editing && (
                <p className="text-xs text-gray-400">No row filters</p>
              )}
              <div className="space-y-2">
                {rowFilters.map((rf, i) => (
                  <div key={i} className="flex items-center gap-2">
                    {editing ? (
                      <>
                        <select
                          value={rf.table}
                          onChange={e => { const copy = [...rowFilters]; copy[i] = { ...copy[i], table: e.target.value }; setRowFilters(copy); }}
                          className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
                        >
                          {ALL_TABLES.map(t => <option key={t} value={t}>{t}</option>)}
                        </select>
                        <input
                          value={rf.condition}
                          onChange={e => { const copy = [...rowFilters]; copy[i] = { ...copy[i], condition: e.target.value }; setRowFilters(copy); }}
                          className="flex-1 text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
                          placeholder="e.g. facility_id = '{{user.facility}}'"
                        />
                        <button onClick={() => setRowFilters(rowFilters.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-600">
                          <X className="w-3.5 h-3.5" />
                        </button>
                      </>
                    ) : (
                      <span className="text-xs text-gray-600 dark:text-gray-400 bg-gray-50 dark:bg-gray-800 rounded px-2 py-1">
                        <span className="font-medium">{rf.table}</span>: {rf.condition}
                      </span>
                    )}
                  </div>
                ))}
                {editing && (
                  <button
                    onClick={() => setRowFilters([...rowFilters, { table: ALL_TABLES[0], condition: '' }])}
                    className="text-xs text-blue-600 dark:text-blue-400 hover:underline"
                  >
                    + Add Row Filter
                  </button>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export function RolePoliciesPanel() {
  const { loading, result, execute } = useApiCall<PolicyRolesResponse>();
  const [syncing, setSyncing] = useState(false);
  const [syncMsg, setSyncMsg] = useState('');
  const [filter, setFilter] = useState('');

  const load = useCallback(() => execute(() => listPolicyRoles()), [execute]);
  useEffect(() => { load(); }, [load]);

  const handleSave = async (roleName: string, update: RolePolicyUpdate) => {
    await updatePolicyRole(roleName, update);
    load();
  };

  const handleSync = async () => {
    setSyncing(true);
    setSyncMsg('');
    try {
      const res = await syncPolicies();
      if (res.data) {
        setSyncMsg(`Synced: ${JSON.stringify(res.data.stats)}`);
      } else {
        setSyncMsg(res.error || 'Sync failed');
      }
      load();
    } finally {
      setSyncing(false);
      setTimeout(() => setSyncMsg(''), 5000);
    }
  };

  const roles = result?.data?.roles ?? [];
  const filtered = filter
    ? roles.filter(r => r.name.toLowerCase().includes(filter.toLowerCase()) || r.domain.toLowerCase().includes(filter.toLowerCase()))
    : roles;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Role Policies</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Manage RBAC policies per role. Changes are saved to Neo4j and reflected in the NL-to-SQL pipeline.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleSync}
            disabled={syncing}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded bg-purple-600 text-white hover:bg-purple-700 disabled:opacity-50 transition-colors"
          >
            {syncing ? <LoadingSpinner size={12} /> : <RefreshCw className="w-3 h-3" />} Sync to Neo4j
          </button>
          <button onClick={load} className="text-xs px-3 py-1.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {syncMsg && (
        <div className="text-xs px-3 py-2 rounded bg-purple-50 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300 border border-purple-200 dark:border-purple-800">
          {syncMsg}
        </div>
      )}

      {/* Filter */}
      <input
        type="text"
        value={filter}
        onChange={e => setFilter(e.target.value)}
        placeholder="Filter roles by name or domain..."
        className="w-full text-sm px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500"
      />

      {/* Loading */}
      {loading && (
        <div className="flex justify-center py-8">
          <LoadingSpinner size={24} />
        </div>
      )}

      {/* Error */}
      {result?.error && (
        <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg p-3 border border-red-200 dark:border-red-800">
          {result.error}
        </div>
      )}

      {/* Role Cards */}
      {!loading && (
        <div className="space-y-2">
          {filtered.map(role => (
            <RoleCard key={role.name} role={role} onSave={handleSave} />
          ))}
          {filtered.length === 0 && !loading && (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">No roles found.</p>
          )}
        </div>
      )}
    </div>
  );
}
