import React from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { threatPatterns } from '../../api/queryvault';
import { PatternsResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

function severityColor(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
  if (s === 'HIGH') return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
  if (s === 'MEDIUM') return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
  if (s === 'LOW') return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
  return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
}

export const ThreatPatternsPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<PatternsResponse>();

  const handleLoad = () => {
    execute(() => threatPatterns());
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Threat Patterns</h2>

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
            'Load Patterns'
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
          <h3 className="text-lg font-medium mb-4">Patterns Overview</h3>

          {/* Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400">Version</p>
              <p className="text-lg font-bold text-gray-800 dark:text-gray-200">{data.version}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400">Total Patterns</p>
              <p className="text-lg font-bold text-gray-800 dark:text-gray-200">{data.total_patterns}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400">Enabled</p>
              <p className="text-lg font-bold text-green-600 dark:text-green-400">{data.enabled}</p>
            </div>
            <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
              <p className="text-xs text-gray-500 dark:text-gray-400">Disabled</p>
              <p className="text-lg font-bold text-gray-500 dark:text-gray-400">{data.disabled}</p>
            </div>
          </div>

          {/* By Category */}
          {data.by_category && Object.keys(data.by_category).length > 0 && (
            <div className="mb-6">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">By Category</h4>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Category</th>
                    <th className="text-right py-2 text-gray-600 dark:text-gray-400">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.by_category)
                    .sort(([, a], [, b]) => b - a)
                    .map(([cat, count]) => (
                      <tr key={cat} className="border-b border-gray-100 dark:border-gray-800">
                        <td className="py-2 pr-3 text-gray-800 dark:text-gray-200">{cat}</td>
                        <td className="py-2 text-right font-medium text-gray-800 dark:text-gray-200">{count}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}

          {/* By Severity */}
          {data.by_severity && Object.keys(data.by_severity).length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-3">By Severity</h4>
              <div className="flex flex-wrap gap-3">
                {Object.entries(data.by_severity).map(([sev, count]) => (
                  <span
                    key={sev}
                    className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium ${severityColor(sev)}`}
                  >
                    {sev}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Raw JSON */}
          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
