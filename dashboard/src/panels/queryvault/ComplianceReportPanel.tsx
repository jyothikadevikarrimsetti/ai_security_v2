import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { complianceReport } from '../../api/queryvault';
import { ComplianceReportResponse } from '../../types/queryvault';
import { JsonViewer } from '../../components/shared/JsonViewer';
import { StatusBadge } from '../../components/shared/StatusBadge';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';

const STANDARD_OPTIONS = [
  { label: 'HIPAA Privacy', value: 'HIPAA_PRIVACY' },
  { label: 'HIPAA Security', value: 'HIPAA_SECURITY' },
  { label: '42 CFR Part 2', value: '42_CFR_PART_2' },
  { label: 'SOX', value: 'SOX' },
  { label: 'GDPR', value: 'GDPR' },
  { label: 'EU AI Act', value: 'EU_AI_ACT' },
  { label: 'ISO 42001', value: 'ISO_42001' },
];

export const ComplianceReportPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<ComplianceReportResponse>();

  const [standard, setStandard] = useState('HIPAA_PRIVACY');
  const [timeRangeDays, setTimeRangeDays] = useState('30');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    execute(() => complianceReport(standard, parseInt(timeRangeDays, 10)));
  };

  const data = result?.data;
  const report = data?.report;

  return (
    <div className="max-w-4xl">
      <h2 className="text-xl font-semibold mb-4">Compliance Report</h2>

      {/* Form Section */}
      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Standard
            </label>
            <select
              value={standard}
              onChange={(e) => setStandard(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            >
              {STANDARD_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

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
                <LoadingSpinner size={16} /> Generating...
              </span>
            ) : (
              'Generate Report'
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
          <h3 className="text-lg font-medium mb-4">Report</h3>

          {/* Summary Cards */}
          {report && (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
                <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
                  <p className="text-xs text-gray-500 dark:text-gray-400">Total Queries</p>
                  <p className="text-xl font-bold text-gray-800 dark:text-gray-200">
                    {report.total_queries_processed ?? '-'}
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
                  <p className="text-xs text-gray-500 dark:text-gray-400">Blocked</p>
                  <p className="text-xl font-bold text-red-600 dark:text-red-400">
                    {report.queries_blocked ?? '-'}
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
                  <p className="text-xs text-gray-500 dark:text-gray-400">Block Rate</p>
                  <p className="text-xl font-bold text-gray-800 dark:text-gray-200">
                    {report.block_rate != null ? `${(report.block_rate * 100).toFixed(1)}%` : '-'}
                  </p>
                </div>
                <div className="bg-gray-50 dark:bg-gray-800 rounded-md p-3 text-center">
                  <p className="text-xs text-gray-500 dark:text-gray-400">Violations</p>
                  <p className="text-xl font-bold text-yellow-600 dark:text-yellow-400">
                    {report.violation_count ?? '-'}
                  </p>
                </div>
              </div>

              {/* Controls Table */}
              {report.controls && Array.isArray(report.controls) && report.controls.length > 0 && (
                <div className="mb-4">
                  <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-2">Controls</h4>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-gray-200 dark:border-gray-700">
                          <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Control ID</th>
                          <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Name</th>
                          <th className="text-left py-2 pr-3 text-gray-600 dark:text-gray-400">Zone</th>
                          <th className="text-left py-2 text-gray-600 dark:text-gray-400">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.controls.map((ctrl: any, idx: number) => (
                          <tr key={idx} className="border-b border-gray-100 dark:border-gray-800">
                            <td className="py-2 pr-3 font-mono text-xs text-gray-700 dark:text-gray-300">
                              {ctrl.control_id}
                            </td>
                            <td className="py-2 pr-3 text-gray-800 dark:text-gray-200">{ctrl.name}</td>
                            <td className="py-2 pr-3 text-gray-600 dark:text-gray-400">{ctrl.zone}</td>
                            <td className="py-2">
                              <StatusBadge value={ctrl.status} />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </>
          )}

          {/* Raw JSON */}
          <JsonViewer rawJson={result.rawJson} />
        </div>
      )}
    </div>
  );
};
