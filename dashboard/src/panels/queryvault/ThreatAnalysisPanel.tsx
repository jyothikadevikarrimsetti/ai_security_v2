import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { threatAnalysis } from '../../api/queryvault';
import { ThreatAnalysisResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

function severityColor(severity: string): string {
  const s = severity.toUpperCase();
  if (s === 'CRITICAL') return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200';
  if (s === 'HIGH') return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200';
  if (s === 'MEDIUM') return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200';
  if (s === 'LOW') return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200';
  return 'bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200';
}

export const ThreatAnalysisPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<ThreatAnalysisResponse>();

  const [timeRangeDays, setTimeRangeDays] = useState('7');
  const [userId, setUserId] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    execute(() => threatAnalysis(parseInt(timeRangeDays, 10), userId || undefined));
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Threat Analysis</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
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
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                User ID <span className="text-gray-400 text-xs">(optional)</span>
              </label>
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                placeholder="Filter by user..."
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              />
            </div>
          </div>

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Analyzing...
              </span>
            ) : (
              'Analyze Threats'
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
          <h3 className="text-lg font-medium mb-4">Threat Analysis</h3>

          {/* Total Threats */}
          <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-6 text-center mb-6">
            <p className="text-xs text-gray-500 dark:text-gray-400 uppercase tracking-wide mb-1">Total Threats</p>
            <p className="text-4xl font-bold text-red-600 dark:text-red-400">{data.total_threats}</p>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
              Last {data.time_range_days} day{data.time_range_days !== 1 ? 's' : ''}
              {data.user_id ? ` | User: ${data.user_id}` : ''}
            </p>
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
            <div className="mb-6">
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

          {/* Top Users */}
          {data.top_users && Object.keys(data.top_users).length > 0 && (
            <div className="mb-6">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Top Users</h4>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">User ID</th>
                    <th className="text-right py-2 text-gray-600 dark:text-gray-400">Count</th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(data.top_users)
                    .sort(([, a], [, b]) => b - a)
                    .map(([uid, count]) => (
                      <tr key={uid} className="border-b border-gray-100 dark:border-gray-800">
                        <td className="py-2 pr-3 font-mono text-xs text-gray-800 dark:text-gray-200">{uid}</td>
                        <td className="py-2 text-right font-medium text-gray-800 dark:text-gray-200">{count}</td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Recent Events */}
          {data.recent_events && data.recent_events.length > 0 && (
            <div className="mb-4">
              <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Recent Events</h4>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-200 dark:border-gray-700">
                      <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Type</th>
                      <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Severity</th>
                      <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">User</th>
                      <th className="text-left py-2 text-gray-600 dark:text-gray-400">Timestamp</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent_events.map((evt: any, idx: number) => (
                      <tr key={idx} className="border-b border-gray-100 dark:border-gray-800">
                        <td className="py-2 pr-3 text-gray-800 dark:text-gray-200">{evt.type ?? evt.event_type ?? '-'}</td>
                        <td className="py-2 pr-3">
                          <StatusBadge value={evt.severity ?? '-'} />
                        </td>
                        <td className="py-2 pr-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                          {evt.user ?? evt.user_id ?? '-'}
                        </td>
                        <td className="py-2 text-xs text-gray-600 dark:text-gray-400">
                          {evt.timestamp ? new Date(evt.timestamp).toLocaleString() : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
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
