import React from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { complianceStandards } from '../../api/queryvault';
import { StandardsResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

export const ComplianceStandardsPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<StandardsResponse>();

  const handleLoad = () => {
    execute(() => complianceStandards());
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Compliance Standards</h2>

      {/* Action */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <button
          type="button"
          onClick={handleLoad}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
          disabled={loading}
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <LoadingSpinner size={16} /> Loading...
            </span>
          ) : (
            'Load Standards'
          )}
        </button>
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
          <h3 className="text-lg font-medium mb-4">Standards</h3>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
            {data.standards.map((std) => (
              <div
                key={std.id}
                className="bg-gray-50 dark:bg-gray-800 rounded-md border border-gray-200 dark:border-gray-700 p-4"
              >
                <div className="flex items-center gap-2 mb-2">
                  <StatusBadge value={std.id} />
                </div>
                <h5 className="text-sm font-medium text-gray-800 dark:text-gray-200 mb-1">{std.name}</h5>
                <p className="text-xs text-gray-600 dark:text-gray-400">{std.description}</p>
              </div>
            ))}
          </div>

          {/* Raw JSON */}
          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
