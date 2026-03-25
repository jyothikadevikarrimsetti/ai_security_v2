import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { pipelineQuery } from '../../api/xensql';
import { PipelineResponse } from '../../types/xensql';
import { FormField } from '../../components/shared/FormField';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const DEFAULT_SCHEMA = JSON.stringify(
  {
    tables: [
      {
        name: 'patients',
        columns: ['id', 'name', 'dob', 'mrn', 'status'],
      },
    ],
  },
  null,
  2,
);

const DIALECT_OPTIONS = [
  { label: '(none)', value: '' },
  { label: 'POSTGRESQL', value: 'POSTGRESQL' },
  { label: 'MYSQL', value: 'MYSQL' },
  { label: 'SQLSERVER', value: 'SQLSERVER' },
  { label: 'ORACLE', value: 'ORACLE' },
];

export const PipelineQueryPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<PipelineResponse>();

  const [question, setQuestion] = useState('');
  const [filteredSchema, setFilteredSchema] = useState(DEFAULT_SCHEMA);
  const [contextualRules, setContextualRules] = useState('');
  const [dialectHint, setDialectHint] = useState('');
  const [sessionId, setSessionId] = useState('');
  const [maxTables, setMaxTables] = useState('10');
  const [tenantId, setTenantId] = useState('');
  const [providerOverride, setProviderOverride] = useState('');
  const [schemaError, setSchemaError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setSchemaError('');

    let parsedSchema: Record<string, any>;
    try {
      parsedSchema = JSON.parse(filteredSchema);
    } catch {
      setSchemaError('Invalid JSON. Please check your schema definition.');
      return;
    }

    const rules = contextualRules
      .split('\n')
      .map((r) => r.trim())
      .filter(Boolean);

    execute(() =>
      pipelineQuery({
        question,
        filtered_schema: parsedSchema,
        contextual_rules: rules,
        dialect_hint: dialectHint || null,
        session_id: sessionId || null,
        conversation_history: [],
        max_tables: parseInt(maxTables, 10) || 10,
        tenant_id: tenantId || '',
        provider_override: providerOverride || null,
      }),
    );
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Pipeline Query</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <FormField
            label="Question"
            type="textarea"
            value={question}
            onChange={setQuestion}
            placeholder="Ask a question in natural language..."
            required
            rows={3}
          />

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Filtered Schema <span className="text-red-500 ml-1">*</span>
            </label>
            <textarea
              value={filteredSchema}
              onChange={(e) => setFilteredSchema(e.target.value)}
              required
              rows={6}
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm font-mono"
            />
            {schemaError && <p className="mt-1 text-xs text-red-500">{schemaError}</p>}
          </div>

          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Contextual Rules
            </label>
            <textarea
              value={contextualRules}
              onChange={(e) => setContextualRules(e.target.value)}
              placeholder="One rule per line..."
              rows={3}
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          <FormField
            label="Dialect Hint"
            type="select"
            value={dialectHint}
            onChange={setDialectHint}
            options={DIALECT_OPTIONS}
          />

          <div className="grid grid-cols-2 gap-4">
            <FormField
              label="Session ID"
              type="text"
              value={sessionId}
              onChange={setSessionId}
              placeholder="Optional session identifier"
            />
            <FormField
              label="Max Tables"
              type="number"
              value={maxTables}
              onChange={setMaxTables}
              min={1}
              max={25}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <FormField
              label="Tenant ID"
              type="text"
              value={tenantId}
              onChange={setTenantId}
              placeholder="Optional tenant identifier"
            />
            <FormField
              label="Provider Override"
              type="text"
              value={providerOverride}
              onChange={setProviderOverride}
              placeholder="Optional provider override"
            />
          </div>

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Querying...
              </span>
            ) : (
              'Submit'
            )}
          </button>
        </form>
      </div>

      {/* Error Display */}
      {result?.error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
          <p className="text-sm text-red-700 dark:text-red-300">{result.error}</p>
        </div>
      )}

      {/* Response Section */}
      {data && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
          <h3 className="text-lg font-medium mb-4">Response</h3>

          {/* Status */}
          <div className="flex items-center gap-3 mb-4">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Status:</span>
            <StatusBadge value={data.status} />
          </div>

          {/* Generated SQL */}
          {data.sql && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Generated SQL</h4>
              <pre className="bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-md p-4 overflow-x-auto">
                <code className="text-sm font-mono text-gray-800 dark:text-gray-200">{data.sql}</code>
              </pre>
            </div>
          )}

          {/* Confidence */}
          {data.confidence && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Confidence</h4>
              <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-4 space-y-3">
                <div className="flex items-center gap-3">
                  <span className="text-sm text-gray-700 dark:text-gray-300">
                    Score: {(data.confidence.score * 100).toFixed(1)}%
                  </span>
                  <StatusBadge value={data.confidence.level} />
                </div>
                {/* Breakdown bars */}
                {(['retrieval_score', 'intent_score', 'generation_score'] as const).map((key) => {
                  const val = data.confidence!.breakdown[key];
                  const label = key.replace('_score', '').replace(/^\w/, (c) => c.toUpperCase());
                  return (
                    <div key={key}>
                      <div className="flex justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
                        <span>{label}</span>
                        <span>{(val * 100).toFixed(1)}%</span>
                      </div>
                      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                        <div
                          className="bg-blue-600 h-2 rounded-full transition-all"
                          style={{ width: `${val * 100}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Ambiguity */}
          {data.ambiguity?.is_ambiguous && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Ambiguity</h4>
              <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md p-4">
                <p className="text-sm text-yellow-800 dark:text-yellow-200 mb-2">{data.ambiguity.reason}</p>
                {data.ambiguity.clarifications.length > 0 && (
                  <div className="mt-2">
                    <p className="text-xs font-medium text-yellow-700 dark:text-yellow-300 mb-1">
                      Clarification Options:
                    </p>
                    <ul className="list-disc list-inside space-y-1">
                      {data.ambiguity.clarifications.map((c, i) => (
                        <li key={i} className="text-sm text-yellow-700 dark:text-yellow-300">
                          <span className="font-medium">{c.label}:</span> {c.rephrased_question}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Explanation */}
          {data.explanation && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Explanation</h4>
              <p className="text-sm text-gray-700 dark:text-gray-300">{data.explanation}</p>
            </div>
          )}

          {/* Metadata Table */}
          {data.metadata && Object.keys(data.metadata).length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Metadata</h4>
              <table className="w-full text-sm">
                <tbody>
                  {Object.entries(data.metadata).map(([key, value]) => (
                    <tr key={key} className="border-b border-gray-100 dark:border-gray-800">
                      <td className="py-1.5 pr-4 font-medium text-gray-600 dark:text-gray-400 whitespace-nowrap">
                        {key}
                      </td>
                      <td className="py-1.5 text-gray-800 dark:text-gray-200">
                        {typeof value === 'object' ? JSON.stringify(value) : String(value)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Raw JSON */}
          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
