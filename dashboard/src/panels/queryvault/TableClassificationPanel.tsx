import { useState, useEffect, useCallback } from 'react';
import { Database, ChevronDown, ChevronRight, Save, Eye, EyeOff, ShieldAlert } from 'lucide-react';
import { useApiCall } from '../../hooks/useApiCall';
import {
  listPolicyTables,
  updatePolicyTable,
  listPolicyColumns,
  updatePolicyColumn,
} from '../../api/queryvault';
import { PolicyTablesResponse, PolicyColumn } from '../../types/policies';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const DOMAINS = ['CLINICAL', 'FINANCIAL', 'ADMINISTRATIVE', 'RESEARCH', 'COMPLIANCE', 'IT_OPERATIONS'];
const VISIBILITY_OPTIONS = ['VISIBLE', 'MASKED', 'HIDDEN'];

const SENSITIVITY_COLORS: Record<number, string> = {
  1: 'bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300',
  2: 'bg-blue-100 text-blue-700 dark:bg-blue-900 dark:text-blue-300',
  3: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900 dark:text-yellow-300',
  4: 'bg-orange-100 text-orange-700 dark:bg-orange-900 dark:text-orange-300',
  5: 'bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300',
};

interface TableRowProps {
  name: string;
  sensitivityLevel: number;
  domain: string;
  columnCount: number;
  onSaveTable: (name: string, sensitivity: number, domain: string) => Promise<void>;
  onSaveColumn: (table: string, col: string, level: number, visibility: string) => Promise<void>;
}

function TableRow({ name, sensitivityLevel, domain, columnCount, onSaveTable, onSaveColumn }: TableRowProps) {
  const [expanded, setExpanded] = useState(false);
  const [editingSensitivity, setEditingSensitivity] = useState(sensitivityLevel);
  const [editingDomain, setEditingDomain] = useState(domain);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [columns, setColumns] = useState<PolicyColumn[]>([]);
  const [loadingCols, setLoadingCols] = useState(false);
  const [editingCol, setEditingCol] = useState<string | null>(null);
  const [colEdits, setColEdits] = useState<Record<string, { level: number; visibility: string }>>({});

  useEffect(() => {
    setEditingSensitivity(sensitivityLevel);
    setEditingDomain(domain);
    setDirty(false);
  }, [sensitivityLevel, domain]);

  const loadColumns = useCallback(async () => {
    setLoadingCols(true);
    try {
      const res = await listPolicyColumns(name);
      if (res.data?.columns) {
        setColumns(res.data.columns);
      }
    } finally {
      setLoadingCols(false);
    }
  }, [name]);

  useEffect(() => {
    if (expanded && columns.length === 0) {
      loadColumns();
    }
  }, [expanded, loadColumns, columns.length]);

  const handleSaveTable = async () => {
    setSaving(true);
    try {
      await onSaveTable(name, editingSensitivity, editingDomain);
      setDirty(false);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveCol = async (col: PolicyColumn) => {
    const edits = colEdits[col.name];
    if (!edits) return;
    setSaving(true);
    try {
      await onSaveColumn(name, col.name, edits.level, edits.visibility);
      setEditingCol(null);
      setColEdits(prev => { const copy = { ...prev }; delete copy[col.name]; return copy; });
      loadColumns();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-700 overflow-hidden">
      {/* Table Header */}
      <div className="flex items-center gap-3 px-4 py-3">
        <button onClick={() => setExpanded(!expanded)} className="text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
          {expanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </button>
        <Database className="w-4 h-4 text-blue-500" />
        <span className="text-sm font-semibold text-gray-800 dark:text-gray-200 flex-1">{name}</span>

        {/* Sensitivity Selector */}
        <div className="flex items-center gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 text-gray-400" />
          <select
            value={editingSensitivity}
            onChange={e => { setEditingSensitivity(Number(e.target.value)); setDirty(true); }}
            className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
          >
            {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>Level {n}</option>)}
          </select>
        </div>

        {/* Domain Selector */}
        <select
          value={editingDomain}
          onChange={e => { setEditingDomain(e.target.value); setDirty(true); }}
          className="text-xs px-2 py-1 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-200"
        >
          <option value="">No domain</option>
          {DOMAINS.map(d => <option key={d} value={d}>{d}</option>)}
        </select>

        <span className="text-[10px] text-gray-500 dark:text-gray-400">{columnCount} cols</span>

        {dirty && (
          <button
            onClick={handleSaveTable}
            disabled={saving}
            className="flex items-center gap-1 text-xs px-2.5 py-1 rounded bg-green-600 text-white hover:bg-green-700 disabled:opacity-50 transition-colors"
          >
            {saving ? <LoadingSpinner size={10} /> : <Save className="w-3 h-3" />} Save
          </button>
        )}
      </div>

      {/* Columns */}
      {expanded && (
        <div className="border-t border-gray-200 dark:border-gray-700">
          {loadingCols ? (
            <div className="flex justify-center py-4"><LoadingSpinner size={16} /></div>
          ) : columns.length === 0 ? (
            <p className="text-xs text-gray-400 text-center py-4">No columns found in Neo4j for this table.</p>
          ) : (
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 dark:bg-gray-800">
                  <th className="px-4 py-2 text-left font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Column</th>
                  <th className="px-4 py-2 text-left font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Type</th>
                  <th className="px-4 py-2 text-center font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Classification</th>
                  <th className="px-4 py-2 text-center font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Visibility</th>
                  <th className="px-4 py-2 text-center font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">PII</th>
                  <th className="px-4 py-2 text-center font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                </tr>
              </thead>
              <tbody>
                {columns.map(col => {
                  const isEditing = editingCol === col.name;
                  const edits = colEdits[col.name] || { level: col.classification_level, visibility: col.default_visibility };
                  const clsBadge = SENSITIVITY_COLORS[col.classification_level] || SENSITIVITY_COLORS[1];

                  return (
                    <tr key={col.name} className="border-t border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                      <td className="px-4 py-2 font-medium text-gray-800 dark:text-gray-200">{col.name}</td>
                      <td className="px-4 py-2 text-gray-500 dark:text-gray-400">{col.data_type}</td>
                      <td className="px-4 py-2 text-center">
                        {isEditing ? (
                          <select
                            value={edits.level}
                            onChange={e => setColEdits({ ...colEdits, [col.name]: { ...edits, level: Number(e.target.value) } })}
                            className="text-xs px-1.5 py-0.5 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                          >
                            {[1, 2, 3, 4, 5].map(n => <option key={n} value={n}>L{n}</option>)}
                          </select>
                        ) : (
                          <span className={`inline-flex px-1.5 py-0.5 rounded-full text-[10px] font-semibold ${clsBadge}`}>
                            L{col.classification_level}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-center">
                        {isEditing ? (
                          <select
                            value={edits.visibility}
                            onChange={e => setColEdits({ ...colEdits, [col.name]: { ...edits, visibility: e.target.value } })}
                            className="text-xs px-1.5 py-0.5 rounded border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800"
                          >
                            {VISIBILITY_OPTIONS.map(v => <option key={v} value={v}>{v}</option>)}
                          </select>
                        ) : (
                          <span className="flex items-center justify-center gap-1">
                            {col.default_visibility === 'VISIBLE' ? (
                              <Eye className="w-3 h-3 text-green-500" />
                            ) : (
                              <EyeOff className="w-3 h-3 text-red-500" />
                            )}
                            <span className="text-gray-600 dark:text-gray-400">{col.default_visibility}</span>
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-center">
                        {col.is_pii ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded-full text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900 dark:text-red-300">PII</span>
                        ) : (
                          <span className="text-gray-400">—</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-center">
                        {isEditing ? (
                          <div className="flex items-center justify-center gap-1">
                            <button
                              onClick={() => handleSaveCol(col)}
                              disabled={saving}
                              className="text-green-600 hover:text-green-700 dark:text-green-400"
                            >
                              <Save className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => { setEditingCol(null); setColEdits(prev => { const c = { ...prev }; delete c[col.name]; return c; }); }}
                              className="text-gray-400 hover:text-gray-600"
                            >
                              ✕
                            </button>
                          </div>
                        ) : (
                          <button
                            onClick={() => { setEditingCol(col.name); setColEdits({ ...colEdits, [col.name]: { level: col.classification_level, visibility: col.default_visibility } }); }}
                            className="text-blue-500 hover:text-blue-700 dark:text-blue-400 text-[10px] hover:underline"
                          >
                            Edit
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

export function TableClassificationPanel() {
  const { loading, result, execute } = useApiCall<PolicyTablesResponse>();

  const load = useCallback(() => execute(() => listPolicyTables()), [execute]);
  useEffect(() => { load(); }, [load]);

  const handleSaveTable = async (name: string, sensitivity: number, domain: string) => {
    await updatePolicyTable(name, sensitivity, domain);
    load();
  };

  const handleSaveColumn = async (table: string, col: string, level: number, visibility: string) => {
    await updatePolicyColumn(table, col, level, visibility);
  };

  // Filter to only tables that have columns (real tables)
  const allTables = result?.data?.tables ?? [];
  const realTables = allTables.filter(t => t.column_count > 0);
  const phantomTables = allTables.filter(t => t.column_count === 0);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-gray-800 dark:text-gray-200">Table Classification</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Set sensitivity levels, domains, and column-level classification. Changes are saved to Neo4j.
          </p>
        </div>
        <button onClick={load} className="text-xs px-3 py-1.5 rounded bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors">
          Refresh
        </button>
      </div>

      {loading && (
        <div className="flex justify-center py-8"><LoadingSpinner size={24} /></div>
      )}

      {result?.error && (
        <div className="text-sm text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 rounded-lg p-3 border border-red-200 dark:border-red-800">
          {result.error}
        </div>
      )}

      {/* Real Tables */}
      {!loading && realTables.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider">
            Active Tables ({realTables.length})
          </h3>
          {realTables.map(t => (
            <TableRow
              key={t.name}
              name={t.name}
              sensitivityLevel={t.sensitivity_level}
              domain={t.domain}
              columnCount={t.column_count}
              onSaveTable={handleSaveTable}
              onSaveColumn={handleSaveColumn}
            />
          ))}
        </div>
      )}

      {/* Phantom Tables (collapsed by default) */}
      {!loading && phantomTables.length > 0 && (
        <details className="group">
          <summary className="text-xs font-semibold text-gray-400 dark:text-gray-500 uppercase tracking-wider cursor-pointer hover:text-gray-600 dark:hover:text-gray-300">
            Schema-only Tables ({phantomTables.length}) — no columns in Neo4j
          </summary>
          <div className="mt-2 space-y-1">
            {phantomTables.map(t => (
              <div key={t.name} className="flex items-center gap-3 px-4 py-2 bg-gray-50 dark:bg-gray-800/50 rounded text-xs text-gray-500 dark:text-gray-400">
                <Database className="w-3 h-3" />
                <span>{t.name}</span>
                <span className={`ml-auto px-1.5 py-0.5 rounded-full text-[10px] font-semibold ${SENSITIVITY_COLORS[t.sensitivity_level] || SENSITIVITY_COLORS[1]}`}>
                  L{t.sensitivity_level}
                </span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}
