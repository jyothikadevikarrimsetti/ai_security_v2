import { useEffect, useState } from 'react';
import { ShieldCheck, Sun, Moon, Users } from 'lucide-react';
import { useAuth } from '../contexts/AuthContext';
import { useTheme } from '../hooks/useTheme';
import { useApiCall } from '../hooks/useApiCall';
import { listPolicyRoles, listMockUsers } from '../api/queryvault';
import { PolicyRoleSummary, PolicyRolesResponse } from '../types/policies';
import { MockUser, MockUsersResponse } from '../types/mockUsers';
import { LoadingSpinner } from '../components/shared/LoadingSpinner';
import {
  DOMAIN_GROUP_ORDER,
  DOMAIN_GROUP_LABELS,
  DOMAIN_GROUP_TEXT_COLORS,
  DOMAIN_ICON,
  CLEARANCE_BADGE,
} from '../constants/userCategories';

function formatRoleName(name: string): string {
  return name
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase())
    .join(' ');
}

export function LoginPage() {
  const { login, loading: loginLoading } = useAuth();
  const { isDark, toggle } = useTheme();
  const { loading: loadingRoles, result: rolesResult, execute: fetchRoles } = useApiCall<PolicyRolesResponse>();
  const { loading: loadingUsers, result: usersResult, execute: fetchUsers } = useApiCall<MockUsersResponse>();
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loggingInRole, setLoggingInRole] = useState<string | null>(null);

  useEffect(() => {
    fetchRoles(() => listPolicyRoles());
    fetchUsers(() => listMockUsers());
  }, []);

  const allRoles = rolesResult?.data?.roles ?? [];
  const users = usersResult?.data?.users ?? [];

  // Only show configured roles (have a domain and clearance > 1)
  const configuredRoles = allRoles.filter(
    (r) => r.domain && r.domain !== '' && r.clearance_level > 1,
  );

  // Build role→user mapping
  const roleUserMap = new Map<string, MockUser>();
  for (const user of users) {
    for (const role of user.ad_roles) {
      if (!roleUserMap.has(role)) {
        roleUserMap.set(role, user);
      }
    }
  }

  // Group roles by domain
  const grouped = DOMAIN_GROUP_ORDER.reduce<Record<string, PolicyRoleSummary[]>>((acc, domain) => {
    const matching = configuredRoles.filter((r) => r.domain === domain);
    if (matching.length > 0) acc[domain] = matching;
    return acc;
  }, {});

  const handleLogin = async (role: PolicyRoleSummary) => {
    const user = roleUserMap.get(role.name);
    if (!user) return;
    setLoginError(null);
    setLoggingInRole(role.name);
    try {
      await login(user);
    } catch (err: any) {
      setLoginError(err.message ?? 'Login failed');
      setLoggingInRole(null);
    }
  };

  const isLoading = loadingRoles || loadingUsers;
  const loadError = rolesResult?.error || usersResult?.error;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-950 flex flex-col">
      {/* Header */}
      <div className="pt-12 pb-8 text-center">
        <div className="flex items-center justify-center gap-3 mb-4">
          <ShieldCheck className="w-10 h-10 text-blue-600 dark:text-blue-400" />
          <div className="text-left">
            <h1 className="text-2xl font-bold text-gray-900 dark:text-gray-100">
              Apollo Hospitals
            </h1>
            <p className="text-sm font-medium text-blue-600 dark:text-blue-400">
              AI Query Security Demo
            </p>
          </div>
        </div>
        <p className="text-sm text-gray-500 dark:text-gray-400 max-w-lg mx-auto">
          Select a role to experience role-based access controls. Each role has different
          clearance levels, domain access, and data visibility policies.
        </p>
      </div>

      {/* Error */}
      {loginError && (
        <div className="max-w-5xl mx-auto px-6 mb-4">
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-3 text-sm text-red-700 dark:text-red-300">
            {loginError}
          </div>
        </div>
      )}

      {/* Role Grid */}
      <div className="flex-1 max-w-5xl mx-auto w-full px-6 pb-12">
        {isLoading ? (
          <div className="flex items-center justify-center gap-2 py-16 text-gray-500 dark:text-gray-400">
            <LoadingSpinner size={20} />
            <span className="text-sm">Loading roles...</span>
          </div>
        ) : loadError ? (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 text-sm text-red-700 dark:text-red-300 text-center">
            Failed to load roles: {loadError}
          </div>
        ) : (
          <div className="space-y-8">
            {Object.entries(grouped).map(([domain, domainRoles]) => {
              const Icon = DOMAIN_ICON[domain] ?? Users;
              const textColor = DOMAIN_GROUP_TEXT_COLORS[domain] ?? 'text-gray-600';
              const domainLabel = DOMAIN_GROUP_LABELS[domain] ?? domain;

              return (
                <div key={domain}>
                  <div className="flex items-center gap-2 mb-3">
                    <Icon className={`w-4 h-4 ${textColor}`} />
                    <span className={`text-xs font-bold uppercase tracking-wider ${textColor}`}>
                      {domainLabel}
                    </span>
                    <div className="flex-1 border-t border-gray-200 dark:border-gray-800 ml-2" />
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                    {domainRoles.map((role) => {
                      const isLogging = loggingInRole === role.name;
                      const badge = CLEARANCE_BADGE[role.clearance_level] ?? CLEARANCE_BADGE[1];
                      const associatedUser = roleUserMap.get(role.name);
                      const hasUser = !!associatedUser;
                      const policyCount = role.allowed_tables.length + role.denied_operations.length;

                      return (
                        <button
                          key={role.name}
                          onClick={() => handleLogin(role)}
                          disabled={loginLoading || !hasUser}
                          className={`text-left p-4 rounded-xl border-2 transition-all bg-white dark:bg-gray-900 ${
                            hasUser
                              ? 'hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500 cursor-pointer border-gray-200 dark:border-gray-800'
                              : 'opacity-50 cursor-not-allowed border-gray-200 dark:border-gray-800'
                          } ${loginLoading ? 'cursor-not-allowed' : ''}`}
                        >
                          <div className="mb-2">
                            <span className="text-sm font-semibold text-gray-900 dark:text-gray-100">
                              {isLogging ? (
                                <span className="flex items-center gap-2">
                                  <LoadingSpinner size={14} /> Signing in...
                                </span>
                              ) : (
                                formatRoleName(role.name)
                              )}
                            </span>
                          </div>

                          {/* Policy summary */}
                          <div className="text-xs text-gray-500 dark:text-gray-400 mb-3">
                            {role.allowed_tables.length > 0 && (
                              <span>{role.allowed_tables.length} table{role.allowed_tables.length > 1 ? 's' : ''}</span>
                            )}
                            {role.allowed_tables.length > 0 && role.denied_operations.length > 0 && ' · '}
                            {role.denied_operations.length > 0 && (
                              <span>{role.denied_operations.length} ops denied</span>
                            )}
                            {policyCount === 0 && 'No policies configured'}
                          </div>

                          {/* Badges */}
                          <div className="flex flex-wrap items-center gap-1.5 mb-2">
                            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold ${badge.color}`}>
                              {badge.label}
                            </span>
                            <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300">
                              {role.domain}
                            </span>
                          </div>

                          {/* Associated user */}
                          <div className="text-[10px] text-gray-400 dark:text-gray-500 truncate">
                            {hasUser ? associatedUser!.display_name : 'No test user available'}
                          </div>
                        </button>
                      );
                    })}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="border-t border-gray-200 dark:border-gray-800 py-4 flex items-center justify-center">
        <button
          onClick={toggle}
          className="flex items-center gap-2 text-xs text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
        >
          {isDark ? <Sun className="w-3.5 h-3.5" /> : <Moon className="w-3.5 h-3.5" />}
          {isDark ? 'Light mode' : 'Dark mode'}
        </button>
      </div>
    </div>
  );
}
