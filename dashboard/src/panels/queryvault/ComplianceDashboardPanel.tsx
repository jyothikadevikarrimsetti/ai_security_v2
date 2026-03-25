import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { complianceDashboard } from '../../api/queryvault';
import { DashboardResponse } from '../../types/queryvault';
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

export const ComplianceDashboardPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<DashboardResponse>();

  const [timeRangeDays, setTimeRangeDays] = useState('7');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    execute(() => complianceDashboard(parseInt(timeRangeDays, 10)));
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Compliance Dashboard</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Time Range (days)
            </label>
            <input
              type="number"
              value={timeRangeDays}
              onChange={(e) => setTimeRangeDays(e.target.value)}
              min={1}
              max={365}
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Loading...
              </span>
            ) : (
              'Load Dashboard'
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
          <h3 className="text-lg font-medium mb-4">Dashboard</h3>

          {/* Total Violations */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-6 text-center mb-6">
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Total Violations</p>
            <p className="text-4xl font-bold text-red-600 dark:text-red-400">{data.total_violations}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Last {data.time_range_days} day{data.time_range_days !== 1 ? 's' : ''}
            </p>
          </div>

          {/* By Type */}
          {data.by_type && Object.keys(data.by_type).length > 0 && (
            <div className="mb-6">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-3">By Type</h4>
              <div className="space-y-2">
                {Object.entries(data.by_type)
                  .sort(([, a], [, b]) => b - a)
                  .map(([type, count]) => {
                    const max = Math.max(...Object.values(data.by_type));
                    const pct = max > 0 ? (count / max) * 100 : 0;
                    return (
                      <div key={type}>
                        <div className="flex justify-between text-xs text-gray-600 dark:text-gray-400 mb-1">
                          <span>{type}</span>
                          <span>{count}</span>
                        </div>
                        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                          <div
                            className="bg-blue-500 h-2 rounded-full transition-all"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
              </div>
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
