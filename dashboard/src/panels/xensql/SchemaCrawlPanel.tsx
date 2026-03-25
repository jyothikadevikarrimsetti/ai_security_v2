import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { schemaCrawl } from '../../api/xensql';
import { CrawlResponse } from '../../types/xensql';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const DEFAULT_ELEMENTS = JSON.stringify(
  [
    {
      id: 'patients',
      text: 'patients table: id, name, dob, mrn, status, department_id',
      metadata: { database: 'clinical' },
    },
  ],
  null,
  2,
);

export const SchemaCrawlPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<CrawlResponse>();

  const [elementsRaw, setElementsRaw] = useState(DEFAULT_ELEMENTS);
  const [parseError, setParseError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setParseError('');

    let parsed: { id: string; text: string; metadata?: Record<string, any> }[];
    try {
      parsed = JSON.parse(elementsRaw);
      if (!Array.isArray(parsed)) {
        setParseError('Elements must be a JSON array.');
        return;
      }
    } catch {
      setParseError('Invalid JSON. Please check your input.');
      return;
    }

    execute(() => schemaCrawl({ elements: parsed }));
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Schema Crawl</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Elements <span className="text-red-500 ml-1">*</span>
            </label>
            <textarea
              value={elementsRaw}
              onChange={(e) => setElementsRaw(e.target.value)}
              required
              rows={10}
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm font-mono"
            />
            {parseError && <p className="mt-1 text-xs text-red-500">{parseError}</p>}
          </div>

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Crawling...
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

          <div className="flex items-center gap-3 mb-4">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Status:</span>
            <StatusBadge value={data.status} />
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Elements Processed</p>
              <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                {data.elements_processed}
              </p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3">
              <p className="text-xs text-gray-500 dark:text-gray-400">Elapsed</p>
              <p className="text-lg font-semibold text-gray-900 dark:text-gray-100">
                {data.elapsed_ms} ms
              </p>
            </div>
          </div>

          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
