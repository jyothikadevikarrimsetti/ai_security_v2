import React, { useState } from 'react';
import { useApiCall } from '../../hooks/useApiCall';
import { gatewayQuery } from '../../api/queryvault';
import { GatewayQueryResponse } from '../../types/queryvault';
import { LoadingSpinner } from '../../components/shared/LoadingSpinner';
import { QueryResultView } from '../../components/shared/QueryResultView';
import { useAuth } from '../../contexts/AuthContext';
import { CLEARANCE_BADGE } from '../../constants/userCategories';
import { User } from 'lucide-react';

export const GatewayQueryPanel: React.FC = () => {
  const { loading, result, execute } = useApiCall<GatewayQueryResponse>();
  const { auth } = useAuth();
  const [question, setQuestion] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!auth?.jwt || !question.trim()) return;
    execute(() => gatewayQuery({ question, jwt_token: auth.jwt }));
  };

  const data = result?.data;
  const badge = auth ? CLEARANCE_BADGE[auth.user.clearance_level] || CLEARANCE_BADGE[1] : null;

  return (
    <div className="max-w-5xl">
      <h2 className="text-xl font-semibold mb-4">Gateway Query</h2>

      <div className="bg-white dark:bg-gray-900 rounded-lg border border-gray-200 dark:border-gray-800 p-6 mb-6">
        {/* Logged-in user context */}
        {auth && (
          <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3 mb-5">
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <User className="w-4 h-4 text-blue-500" />
              <span className="font-medium text-gray-900 dark:text-gray-100">{auth.user.display_name}</span>
              {badge && (
                <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${badge.color}`}>{badge.label}</span>
              )}
              <span className="text-xs px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-900/40 text-purple-700 dark:text-purple-300 font-medium">
                {auth.user.domain}
              </span>
              <span className="text-xs text-gray-500 dark:text-gray-400">
                Roles: {auth.user.ad_roles.join(', ')}
              </span>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
              Question <span className="text-red-500 ml-1">*</span>
            </label>
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              required
              rows={3}
              placeholder="Ask a question about the data..."
              className="w-full px-3 py-2 rounded-md border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-800 text-gray-900 dark:text-gray-100 placeholder-gray-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
            />
          </div>

          <button
            type="submit"
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg disabled:opacity-50"
            disabled={loading || !question.trim()}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <LoadingSpinner size={16} /> Querying...
              </span>
            ) : (
              'Submit Query'
            )}
          </button>
        </form>
      </div>

      {result?.error && (
        <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
          <p className="text-sm text-red-700 dark:text-red-300">{result.error}</p>
        </div>
      )}

      {data && <QueryResultView data={data} rawJson={result.rawJson} />}
    </div>
  );
};
