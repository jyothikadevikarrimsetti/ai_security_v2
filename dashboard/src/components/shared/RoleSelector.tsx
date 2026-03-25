import React, { useEffect, useState } from 'react';
import { Users } from 'lucide-react';
import { useApiCall } from '../../hooks/useApiCall';
import { listMockUsers, generateMockToken } from '../../api/queryvault';
import { MockUser, MockUsersResponse } from '../../types/mockUsers';
import { LoadingSpinner } from './LoadingSpinner';
import {
  CATEGORY_ORDER,
  CATEGORY_ICON,
  CATEGORY_COLOR,
  CLEARANCE_BADGE,
} from '../../constants/userCategories';

interface RoleSelectorProps {
  onTokenGenerated: (jwt: string, user: MockUser) => void;
  selectedOid: string | null;
}

export const RoleSelector: React.FC<RoleSelectorProps> = ({ onTokenGenerated, selectedOid }) => {
  const { loading: loadingUsers, result: usersResult, execute: fetchUsers } = useApiCall<MockUsersResponse>();
  const [generatingOid, setGeneratingOid] = useState<string | null>(null);

  useEffect(() => {
    fetchUsers(() => listMockUsers());
  }, []);

  const users = usersResult?.data?.users ?? [];

  const grouped = CATEGORY_ORDER.reduce<Record<string, MockUser[]>>((acc, cat) => {
    const items = users.filter((u) => u.category === cat);
    if (items.length > 0) acc[cat] = items;
    return acc;
  }, {});

  const handleSelect = async (user: MockUser) => {
    setGeneratingOid(user.oid);
    try {
      const result = await generateMockToken(user.oid);
      if (result.data) {
        onTokenGenerated(result.data.jwt_token, user);
      }
    } finally {
      setGeneratingOid(null);
    }
  };

  if (loadingUsers) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-gray-500 dark:text-gray-400">
        <LoadingSpinner size={16} /> Loading test users...
      </div>
    );
  }

  if (usersResult?.error) {
    return (
      <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-3 text-sm text-red-700 dark:text-red-300">
        Failed to load test users: {usersResult.error}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([category, categoryUsers]) => {
        const Icon = CATEGORY_ICON[category] ?? Users;
        const colorClass = CATEGORY_COLOR[category] ?? 'text-gray-600';

        return (
          <div key={category}>
            <div className="flex items-center gap-1.5 mb-2">
              <Icon className={`w-3.5 h-3.5 ${colorClass}`} />
              <span className={`text-xs font-semibold uppercase tracking-wider ${colorClass}`}>
                {category}
              </span>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
              {categoryUsers.map((user) => {
                const isSelected = selectedOid === user.oid;
                const isGenerating = generatingOid === user.oid;
                const badge = CLEARANCE_BADGE[user.clearance_level] ?? CLEARANCE_BADGE[1];

                return (
                  <button
                    key={user.oid}
                    type="button"
                    onClick={() => handleSelect(user)}
                    disabled={isGenerating}
                    className={`text-left p-3 rounded-lg border transition-all ${
                      isSelected
                        ? 'border-blue-500 dark:border-blue-400 bg-blue-50 dark:bg-blue-900/20 ring-1 ring-blue-500 dark:ring-blue-400'
                        : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600 hover:bg-gray-50 dark:hover:bg-gray-800/50'
                    } ${user.employment_status === 'TERMINATED' ? 'opacity-70' : ''}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-sm font-medium text-gray-900 dark:text-gray-100 truncate">
                        {isGenerating ? (
                          <span className="flex items-center gap-1.5">
                            <LoadingSpinner size={12} /> Generating...
                          </span>
                        ) : (
                          user.display_name
                        )}
                      </span>
                    </div>
                    <div className="text-xs text-gray-500 dark:text-gray-400 mb-1.5 truncate">
                      {user.department}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium ${badge.color}`}>
                        {badge.label}
                      </span>
                      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                        {user.domain}
                      </span>
                      {user.employment_status === 'TERMINATED' && (
                        <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-400">
                          TERMINATED
                        </span>
                      )}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
};
