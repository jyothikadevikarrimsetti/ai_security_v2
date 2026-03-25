import React, { useState, useCallback } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { listAlerts, acknowledgeAlert, resolveAlert } from '../../api/queryvault';
import { AlertsResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

export const AlertsPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<AlertsResponse>();

  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [userId, setUserId] = useState('');
  const [timeRangeDays, setTimeRangeDays] = useState('7');
  const [limit, setLimit] = useState('50');

  const [actionStatus, setActionStatus] = useState<Record<string, { type: string; message: string }>>({});

  const fetchAlerts = useCallback(() => {
    execute(() =>
      listAlerts({
        severity: severity || undefined,
        status: status || undefined,
        user_id: userId || undefined,
        time_range_days: parseInt(timeRangeDays, 10),
        limit: parseInt(limit, 10),
      }),
    );
  }, [execute, severity, status, userId, timeRangeDays, limit]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchAlerts();
  };

  const handleAcknowledge = async (alertId: string) => {
    setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'loading', message: 'Acknowledging...' } }));
    const res = await acknowledgeAlert(alertId);
    if (res.error) {
      setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'error', message: res.error! } }));
    } else {
      setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'success', message: 'Acknowledged' } }));
      fetchAlerts();
    }
  };

  const handleResolve = async (alertId: string) => {
    setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'loading', message: 'Resolving...' } }));
    const res = await resolveAlert(alertId);
    if (res.error) {
      setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'error', message: res.error! } }));
    } else {
      setActionStatus((prev) => ({ ...prev, [alertId]: { type: 'success', message: 'Resolved' } }));
      fetchAlerts();
    }
  };

  const data = result?.data;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Alerts</h2>

      {/* Filter Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Severity</label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              >
                <option value="">All</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
              >
                <option value="">All</option>
                <option value="OPEN">OPEN</option>
                <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                <option value="RESOLVED">RESOLVED</option>
              </select>
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
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Limit</label>
              <input
                type="number"
                value={limit}
                onChange={(e) => setLimit(e.target.value)}
                min={1}
                max={500}
                className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
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
                <LoadingSpinner size={16} /> Loading...
              </span>
            ) : (
              'Fetch Alerts'
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

      {/* Results Section */}
      {data && (
        <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-medium">Alerts</h3>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              Total: {data.total} | Showing {data.offset + 1}-{Math.min(data.offset + data.limit, data.total)} | Limit: {data.limit}
            </span>
          </div>

          {data.alerts.length === 0 ? (
            <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-8">No alerts found.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-200 dark:border-gray-700">
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Alert ID</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Severity</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Status</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Event Type</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">User</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Title</th>
                    <th className="text-left py-2 pr-2 text-gray-600 dark:text-gray-400">Created</th>
                    <th className="text-left py-2 text-gray-600 dark:text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {data.alerts.map((alert: any) => {
                    const alertId = alert.alert_id ?? alert.id ?? '';
                    const truncId = alertId.length > 12 ? alertId.slice(0, 12) + '...' : alertId;
                    const rowAction = actionStatus[alertId];
                    return (
                      <tr key={alertId} className="border-b border-gray-100 dark:border-gray-800">
                        <td className="py-2 pr-2 font-mono text-xs text-gray-700 dark:text-gray-300" title={alertId}>
                          {truncId}
                        </td>
                        <td className="py-2 pr-2">
                          <StatusBadge value={alert.severity ?? '-'} />
                        </td>
                        <td className="py-2 pr-2">
                          <StatusBadge value={alert.status ?? '-'} />
                        </td>
                        <td className="py-2 pr-2 text-gray-800 dark:text-gray-200">
                          {alert.event_type ?? '-'}
                        </td>
                        <td className="py-2 pr-2 font-mono text-xs text-gray-700 dark:text-gray-300">
                          {alert.user_id ?? '-'}
                        </td>
                        <td className="py-2 pr-2 text-gray-800 dark:text-gray-200 max-w-[200px] truncate">
                          {alert.title ?? '-'}
                        </td>
                        <td className="py-2 pr-2 text-xs text-gray-600 dark:text-gray-400 whitespace-nowrap">
                          {alert.created_at ? new Date(alert.created_at).toLocaleString() : '-'}
                        </td>
                        <td className="py-2">
                          <div className="flex items-center gap-1">
                            <button
                              type="button"
                              onClick={() => handleAcknowledge(alertId)}
                              className="px-2 py-1 text-xs rounded bg-yellow-100 hover:bg-yellow-200 text-yellow-800 dark:bg-yellow-900 dark:hover:bg-yellow-800 dark:text-yellow-200 disabled:opacity-50"
                              disabled={rowAction?.type === 'loading'}
                            >
                              Ack
                            </button>
                            <button
                              type="button"
                              onClick={() => handleResolve(alertId)}
                              className="px-2 py-1 text-xs rounded bg-green-100 hover:bg-green-200 text-green-800 dark:bg-green-900 dark:hover:bg-green-800 dark:text-green-200 disabled:opacity-50"
                              disabled={rowAction?.type === 'loading'}
                            >
                              Resolve
                            </button>
                          </div>
                          {rowAction && (
                            <p
                              className={`text-xs mt-1 ${
                                rowAction.type === 'error'
                                  ? 'text-red-600 dark:text-red-400'
                                  : rowAction.type === 'success'
                                    ? 'text-green-600 dark:text-green-400'
                                    : 'text-gray-500 dark:text-gray-400'
                              }`}
                            >
                              {rowAction.message}
                            </p>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Raw JSON */}
          <div className="mt-4">
            <JsonViewer rawJson={result.rawJson} />
          </div>
        </div>
      )}
    </div>
  );
};
