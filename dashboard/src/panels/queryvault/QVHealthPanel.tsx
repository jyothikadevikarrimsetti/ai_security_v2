import React from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { gatewayHealth } from '../../api/queryvault';
import { GatewayHealthResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

function componentStatusColor(status: string): string {
  const s = status.toUpperCase();
  if (s === 'OK' || s === 'HEALTHY' || s === 'CONNECTED') return 'bg-green-100 dark:bg-green-900 border-green-300 dark:border-green-700';
  if (s === 'DEGRADED' || s === 'WARN') return 'bg-yellow-100 dark:bg-yellow-900 border-yellow-300 dark:border-yellow-700';
  return 'bg-red-100 dark:bg-red-900 border-red-300 dark:border-red-700';
}

export const QVHealthPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<GatewayHealthResponse>();

  const handleCheck = () => {
    execute(() => gatewayHealth());
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">QueryVault Health</h2>

      {/* Action */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <button
          type="button"
          onClick={handleCheck}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
          disabled={loading}
        >
          {loading ? (
            <span className="flex items-center gap-2">
              <LoadingSpinner size={16} /> Checking...
            </span>
          ) : (
            'Check Health'
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
          <h3 className="text-lg font-medium mb-4">Health Status</h3>

          <div className="flex items-center gap-3 mb-4">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Status:</span>
            <StatusBadge value={data.status} />
          </div>

          <div className="flex items-center gap-3 mb-6">
            <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Version:</span>
            <span className="text-sm text-gray-800 dark:text-gray-200">{data.version}</span>
          </div>

          {/* Components Grid */}
          <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-3">Components</h4>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
            {Object.entries(data.components).map(([name, status]) => (
              <div
                key={name}
                className={`rounded-md border p-3 ${componentStatusColor(status)}`}
              >
                <p className="text-xs font-medium text-gray-600 dark:text-gray-400 mb-1">{name}</p>
                <StatusBadge value={status} />
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
