import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { schemaCatalog } from '../../api/xensql';
import { CatalogResponse } from '../../types/xensql';
import { FormField } from '../../components/shared/FormField';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

export const SchemaCatalogPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<CatalogResponse>();

  const [database, setDatabase] = useState('');

  const handleFetch = (e: React.FormEvent) => {
    e.preventDefault();
    execute(() => schemaCatalog(database || undefined));
  };

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Schema Catalog</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleFetch}>
          <FormField
            label="Database"
            type="text"
            value={database}
            onChange={setDatabase}
            placeholder="Filter by database name..."
          />

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Fetching...
              </span>
            ) : (
              'Fetch'
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
      {result?.data && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
          <h3 className="text-lg font-medium mb-4">Response</h3>
          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
