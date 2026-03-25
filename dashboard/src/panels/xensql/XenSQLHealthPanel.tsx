import React, { useState, useEffect, useRef, useCallback } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { pipelineHealth } from '../../api/xensql';
import { HealthResponse } from '../../types/xensql';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const AUTO_REFRESH_INTERVAL_MS = 15_000;

export const XenSQLHealthPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<HealthResponse>();
  const [autoRefresh, setAutoRefresh] = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const checkHealth = useCallback(() => {
    execute(() => pipelineHealth());
  }, [execute]);

  useEffect(() => {
    if (autoRefresh) {
      checkHealth();
      timerRef.current = setInterval(checkHealth, AUTO_REFRESH_INTERVAL_MS);
    }
    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [autoRefresh, checkHealth]);

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">XenSQL Health</h2>

      {/* Controls */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <div className="flex items-center gap-4">
          <button
            type="button"
            onClick={checkHealth}
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

          <label className="flex items-center gap-2 text-sm text-gray-700 dark:text-gray-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
              className="rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
            />
            Auto-refresh (every 15s)
          </label>
        </div>
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

          {/* Status + Version */}
          <div className="flex items-center gap-4 mb-6">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Status:</span>
              <StatusBadge value={data.status} />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Version:</span>
              <span className="text-sm text-gray-800 dark:text-gray-200">{data.version}</span>
            </div>
            {data.service && (
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-gray-600 dark:text-gray-400">Service:</span>
                <span className="text-sm text-gray-800 dark:text-gray-200">{data.service}</span>
              </div>
            )}
          </div>

          {/* Dependencies Grid */}
          {data.dependencies && Object.keys(data.dependencies).length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-3">Dependencies</h4>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {Object.entries(data.dependencies).map(([name, healthy]) => (
                  <div
                    key={name}
                    className="flex items-center gap-2 bg-gray-50 dark:bg-gray-800 rounded-md p-3"
                  >
                    <span
                      className={`inline-block w-3 h-3 rounded-full ${
                        healthy ? 'bg-green-500' : 'bg-red-500'
                      }`}
                    />
                    <span className="text-sm text-gray-800 dark:text-gray-200">{name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
