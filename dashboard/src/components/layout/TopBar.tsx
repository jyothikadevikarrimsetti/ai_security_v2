import { Sun, Moon, Shield, LogOut } from 'lucide-react';
import { useHealth } from '../../hooks/useHealthPolling';
import { useTheme } from '../../hooks/useTheme';
import { useAuth } from '../../contexts/AuthContext';
import { CLEARANCE_BADGE } from '../../constants/userCategories';

function statusColor(status: 'ok' | 'degraded' | 'unreachable'): string {
  switch (status) {
    case 'ok':
      return 'bg-green-500';
    case 'degraded':
      return 'bg-yellow-500';
    case 'unreachable':
      return 'bg-red-500';
  }
}

interface TopBarProps {
  onConfigurePolicies?: () => void;
}

export default function TopBar({ onConfigurePolicies }: TopBarProps) {
  const { isDark, toggle } = useTheme();
  const health = useHealth();
  const { auth, logout } = useAuth();
  const badge = auth ? CLEARANCE_BADGE[auth.user.clearance_level] || CLEARANCE_BADGE[1] : null;

  return (
    <header className="h-14 border-b border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-900 flex items-center justify-between px-4 flex-shrink-0">
      {/* Left: Title */}
      <h1 className="text-sm font-semibold text-gray-800 dark:text-gray-100">
        XenSQL + QueryVault Dashboard
      </h1>

      {/* Center: Health indicators */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-1.5">
          <span className={`w-2.5 h-2.5 rounded-full ${statusColor(health.xensql.status)}`} />
          <span className="text-xs text-gray-600 dark:text-gray-300">XenSQL</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className={`w-2.5 h-2.5 rounded-full ${statusColor(health.queryvault.status)}`} />
          <span className="text-xs text-gray-600 dark:text-gray-300">QueryVault</span>
        </div>
      </div>

      {/* Right: Actions */}
      <div className="flex items-center gap-3">
        {onConfigurePolicies && (
          <button
            onClick={onConfigurePolicies}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-blue-50 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 hover:bg-blue-100 dark:hover:bg-blue-900/50 transition-colors font-medium"
          >
            <Shield className="w-3.5 h-3.5" /> Configure Policies
          </button>
        )}

        {auth && (
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800">
            <span className="text-xs font-medium text-gray-700 dark:text-gray-300">{auth.user.display_name}</span>
            {badge && (
              <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded-full ${badge.color}`}>
                {badge.label}
              </span>
            )}
          </div>
        )}

        <button
          onClick={toggle}
          className="p-2 rounded-md text-gray-500 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
          aria-label="Toggle dark mode"
        >
          {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {auth && (
          <button
            onClick={logout}
            className="flex items-center gap-1 text-xs text-gray-500 dark:text-gray-400 hover:text-red-600 dark:hover:text-red-400 transition-colors"
          >
            <LogOut className="w-3.5 h-3.5" /> Logout
          </button>
        )}
      </div>
    </header>
  );
}
